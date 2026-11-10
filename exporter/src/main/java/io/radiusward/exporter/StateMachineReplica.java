/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.aeron.Aeron;
import io.aeron.ChannelUri;
import io.aeron.FragmentAssembler;
import io.aeron.Image;
import io.aeron.Subscription;
import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.RecordingLog;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.cluster.service.LogApplier;
import io.radiusward.cluster.service.SnapshotCodec;
import io.radiusward.protocol.MessageHeaderDecoder;
import java.io.File;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.IdleStrategy;
import org.agrona.concurrent.SleepingMillisIdleStrategy;

/**
 * A second copy of the accounting state machine, driven by the committed log through the same
 * {@link LogApplier} as the clustered service. It tells the exporter what the cluster decided for every event
 * (applied, duplicate, stale, rejected) and what each session looks like afterwards, without asking the
 * cluster. Starts from the cluster's latest snapshot at or below a position, then follows the log.
 */
public final class StateMachineReplica implements ClusterLogReader.Listener {

    /** What the cluster decided for one accounting event; called after the state machine applied it. */
    public interface OutcomeListener {
        void onCommand(long position, long timestamp, int outcome, LogApplier applier);
    }

    private static final int SERVICE_ID = 0;
    private static final String SNAPSHOT_CHANNEL = "aeron:ipc?term-length=1m";

    private final LogApplier applier;
    private final OutcomeListener outcomes;
    private long position;

    private StateMachineReplica(AccountingStateMachine machine, long position, OutcomeListener outcomes) {
        machine.memberState(false); // users, devices, CoA identities stay with the member (ADR 0036): same JVM
        this.applier = new LogApplier(machine);
        this.position = position;
        this.outcomes = outcomes;
    }

    /** A replica of an empty cluster, to read the log from position 0. */
    public static StateMachineReplica empty(AccountingStateMachine.Settings settings, OutcomeListener outcomes) {
        return new StateMachineReplica(new AccountingStateMachine(settings), 0, outcomes);
    }

    /**
     * A replica restored from the latest service snapshot at or below {@code maxPosition} in {@code clusterDir}
     * (or empty at position 0 if there is none); {@link #position()} is where reading the log has to start.
     */
    public static StateMachineReplica fromSnapshot(
            Aeron aeron,
            AeronArchive archive,
            File clusterDir,
            long maxPosition,
            AccountingStateMachine.Settings settings,
            int streamId,
            OutcomeListener outcomes) {
        RecordingLog.Entry snapshot = latestSnapshot(clusterDir, maxPosition);
        AccountingStateMachine machine = new AccountingStateMachine(settings);
        machine.memberState(false);
        if (snapshot == null) {
            return new StateMachineReplica(machine, 0, outcomes);
        }
        loadSnapshot(aeron, archive, snapshot.recordingId, machine, streamId);
        return new StateMachineReplica(machine, snapshot.logPosition, outcomes);
    }

    private static RecordingLog.Entry latestSnapshot(File clusterDir, long maxPosition) {
        try (RecordingLog recordingLog = new RecordingLog(clusterDir, false)) {
            RecordingLog.Entry best = null;
            for (RecordingLog.Entry e : recordingLog.entries()) {
                if (e.isValid
                        && e.type == RecordingLog.ENTRY_TYPE_SNAPSHOT
                        && e.serviceId == SERVICE_ID
                        && e.logPosition <= maxPosition
                        && (best == null || e.logPosition > best.logPosition)) {
                    best = e;
                }
            }
            return best;
        }
    }

    private static void loadSnapshot(
            Aeron aeron, AeronArchive archive, long recordingId, AccountingStateMachine machine, int streamId) {
        long stop = archive.getStopPosition(recordingId);
        long start = archive.getStartPosition(recordingId);
        long sessionId = archive.startReplay(recordingId, start, stop - start, SNAPSHOT_CHANNEL, streamId);
        SnapshotCodec codec = new SnapshotCodec();
        MessageHeaderDecoder header = new MessageHeaderDecoder();
        FragmentAssembler assembler = new FragmentAssembler((buffer, offset, length, h) -> {
            header.wrap(buffer, offset);
            if (header.schemaId() == MessageHeaderDecoder.SCHEMA_ID) { // skip Aeron's own snapshot records
                codec.onMessage(machine, buffer, offset, length);
            }
        });
        IdleStrategy idle = new SleepingMillisIdleStrategy(1);
        try (Subscription subscription =
                aeron.addSubscription(ChannelUri.addSessionId(SNAPSHOT_CHANNEL, (int) sessionId), streamId)) {
            Image image;
            while ((image = subscription.imageBySessionId((int) sessionId)) == null) {
                idle.idle();
            }
            while (!codec.complete()) {
                int fragments = image.poll(assembler, 64);
                if (fragments == 0) {
                    if (image.isEndOfStream() || image.isClosed()) {
                        throw new IllegalStateException("snapshot recording " + recordingId + " has no footer");
                    }
                    idle.idle();
                }
            }
        }
    }

    @Override
    public void onSessionMessage(long position, long timestamp, DirectBuffer buffer, int offset, int length) {
        this.position = position;
        int outcome = applier.apply(buffer, offset, position, timestamp);
        if (outcome >= 0) {
            applier.claimSweepTimer(); // the service schedules the timer here; the replica records the flag
            if (outcomes != null) {
                outcomes.onCommand(position, timestamp, outcome, applier);
            }
        } else if (outcome == LogApplier.AUTH_RESERVATION) {
            applier.claimSweepTimer(); // as the service does after a reservation
        }
    }

    @Override
    public void onTimer(long position, long correlationId, long timestamp) {
        this.position = position;
        applier.onTimer(correlationId, timestamp);
    }

    public AccountingStateMachine machine() {
        return applier.machine();
    }

    /** Log position the replica has applied up to. */
    public long position() {
        return position;
    }
}
