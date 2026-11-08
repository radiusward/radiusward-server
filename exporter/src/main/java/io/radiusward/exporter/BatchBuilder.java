/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.cluster.service.LogApplier;
import io.radiusward.cluster.service.Outcomes;
import io.radiusward.cluster.service.SessionStore;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.protocol.AccountingCommandDecoder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Turns what the replica decided into the next {@link Batch}: applied and stale events (duplicates and rejected
 * events are dropped) and the latest snapshot of every session that changed, including sessions closed by
 * Accounting-On/Off or the idle timeout. Entries at or below the start position are only replayed into the
 * replica, never exported again.
 */
public final class BatchBuilder implements StateMachineReplica.OutcomeListener, AccountingStateMachine.SessionListener {

    private final String sink;
    private final boolean keepEvents;
    private StateMachineReplica replica;
    private long startPosition;
    private long fromPosition;
    private long lastEventTime;
    private final List<ExportEvent> events = new ArrayList<>();
    private final Map<UUID, SessionSnapshot> sessions = new LinkedHashMap<>();

    public BatchBuilder(String sink, boolean keepEvents) {
        this.sink = sink;
        this.keepEvents = keepEvents;
    }

    /** Connects the builder to the replica feeding it; nothing at or below {@code startPosition} is exported. */
    public void attach(StateMachineReplica replica, long startPosition) {
        this.replica = replica;
        this.startPosition = startPosition;
        this.fromPosition = startPosition;
        replica.machine().sessionListener(this);
        events.clear();
        sessions.clear();
    }

    @Override
    public void onCommand(long position, long timestamp, int outcome, LogApplier applier) {
        if (position <= startPosition) {
            return;
        }
        lastEventTime = timestamp;
        if (outcome != Outcomes.APPLIED && outcome != Outcomes.STALE) {
            return;
        }
        AccountingCommandDecoder c = applier.command();
        int statusType = (int) c.statusType();
        boolean nasWide = statusType == AccountingStateMachine.STATUS_ACCOUNTING_ON
                || statusType == AccountingStateMachine.STATUS_ACCOUNTING_OFF;
        UUID sessionKey = nasWide ? null : new UUID(c.sessionKeyHi(), c.sessionKeyLo());
        String acctSessionId = c.sessionId();
        byte[] raw = new byte[c.rawAttributesLength()];
        c.getRawAttributes(raw, 0, raw.length);
        Long sessionTime = c.flags().sessionTimePresent() ? c.sessionTime() : null;
        if (keepEvents) {
            events.add(new ExportEvent(
                    new UUID(c.exactKeyHi(), c.exactKeyLo()),
                    position,
                    timestamp,
                    c.nasId(),
                    c.gatewayId(),
                    sessionKey,
                    acctSessionId,
                    statusType,
                    outcome == Outcomes.APPLIED ? ExportEvent.EventOutcome.APPLIED : ExportEvent.EventOutcome.STALE,
                    sessionTime,
                    c.flags().eventTimestampPresent() ? c.eventTimestamp() : null,
                    c.inputOctets(),
                    c.outputOctets(),
                    raw));
        }
        if (outcome != Outcomes.APPLIED || sessionKey == null) {
            return; // stale events do not change the session; NAS-wide events close sessions via the listener
        }
        boolean stop = statusType == AccountingStateMachine.STATUS_STOP;
        SessionStore store = replica.machine().store();
        int slot = store.find(c.sessionKeyHi(), c.sessionKeyLo());
        boolean stopped = slot >= 0 ? store.state(slot) == SessionStore.STOPPED : stop;
        sessions.put(
                sessionKey,
                new SessionSnapshot(
                        sessionKey,
                        position,
                        c.nasId(),
                        acctSessionId,
                        stopped ? SessionSnapshot.State.STOPPED : SessionSnapshot.State.ACTIVE,
                        stop ? SessionSnapshot.CloseCause.STOP : SessionSnapshot.CloseCause.NONE,
                        statusType,
                        sessionTime,
                        c.inputOctets(),
                        c.outputOctets(),
                        timestamp,
                        statusType == AccountingStateMachine.STATUS_START ? timestamp : null,
                        stop ? timestamp : null,
                        raw));
    }

    @Override
    public void onSessionClosed(int slot, int cause, long now) {
        long position = replica.position();
        if (position <= startPosition) {
            return;
        }
        SessionStore store = replica.machine().store();
        UUID key = new UUID(store.keyHi(slot), store.keyLo(slot));
        boolean hasTime = (store.flags(slot) & AccountingStateMachine.FLAG_SESSION_TIME) != 0;
        sessions.put(
                key,
                new SessionSnapshot(
                        key,
                        position,
                        store.nasId(slot),
                        null,
                        SessionSnapshot.State.STOPPED,
                        cause == CAUSE_NAS_RESTART
                                ? SessionSnapshot.CloseCause.NAS_RESTART
                                : SessionSnapshot.CloseCause.IDLE_TIMEOUT,
                        store.statusType(slot),
                        hasTime ? store.sessionTime(slot) : null,
                        store.inputOctets(slot),
                        store.outputOctets(slot),
                        now,
                        null,
                        now,
                        null));
    }

    /** Rows waiting to be written (events plus distinct sessions). */
    public int rows() {
        return events.size() + sessions.size();
    }

    /** Whether the replica has read past the last batch (also through entries without rows, e.g. checkpoints). */
    public boolean hasProgress() {
        return replica.position() > fromPosition;
    }

    /** The batch up to the replica's position; starts the next one. */
    public Batch take(long epoch) {
        long to = replica.position();
        Batch batch = new Batch(
                sink, epoch, fromPosition, to, lastEventTime, List.copyOf(events), List.copyOf(sessions.values()));
        fromPosition = to;
        events.clear();
        sessions.clear();
        return batch;
    }
}
