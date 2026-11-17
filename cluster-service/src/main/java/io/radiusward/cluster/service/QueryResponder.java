/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import io.aeron.cluster.service.ClientSession;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.SessionQueryDecoder;
import io.radiusward.protocol.SessionReportEncoder;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.protocol.StateQueryDecoder;
import io.radiusward.protocol.StateReportEncoder;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The read-only questions the service answers from the replicated state: the state machine's counters and digest,
 * a session by its key, a user's active sessions, and pages of sessions for the gateways' store sweep (ADR 0036).
 * They change nothing, so the answer may differ between members only by when it is asked. Reuses its encoders and
 * buffers; called on the service's thread only.
 */
final class QueryResponder {

    /** At most this many sessions in one report. */
    static final int MAX_LISTED = 64;

    /** Sends an answer to the session that asked. */
    interface Egress {
        void send(ClientSession session, DirectBuffer buffer, int length);
    }

    private final AccountingStateMachine machine;
    private final Egress egress;
    private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
    private final StateQueryDecoder stateQueryDecoder = new StateQueryDecoder();
    private final StateReportEncoder stateReportEncoder = new StateReportEncoder();
    private final SessionQueryDecoder sessionQueryDecoder = new SessionQueryDecoder();
    private final SessionReportEncoder sessionReportEncoder = new SessionReportEncoder();
    private final UnsafeBuffer reply = new UnsafeBuffer(new byte[512]);
    /** Reports with lists of sessions (ADR 0036): at most {@link #MAX_LISTED} entries of up to 160 bytes. */
    private final UnsafeBuffer listBuffer = new UnsafeBuffer(new byte[MAX_LISTED * 160 + 64]);

    private final UnsafeBuffer identityScratch = new UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);
    private final io.radiusward.protocol.UserSessionsQueryDecoder userSessionsQueryDecoder =
            new io.radiusward.protocol.UserSessionsQueryDecoder();
    private final io.radiusward.protocol.UserSessionsReportEncoder userSessionsReportEncoder =
            new io.radiusward.protocol.UserSessionsReportEncoder();
    private final io.radiusward.protocol.SessionPageQueryDecoder sessionPageQueryDecoder =
            new io.radiusward.protocol.SessionPageQueryDecoder();
    private final io.radiusward.protocol.SessionPageReportEncoder sessionPageReportEncoder =
            new io.radiusward.protocol.SessionPageReportEncoder();

    QueryResponder(AccountingStateMachine machine, Egress egress) {
        this.machine = machine;
        this.egress = egress;
    }

    /** The state machine's counters and digest ({@code admin state}, {@code verify-acks}). */
    void state(ClientSession session, DirectBuffer buffer, int offset, MessageHeaderDecoder header) {
        stateQueryDecoder.wrapAndApplyHeader(buffer, offset, header);
        stateReportEncoder
                .wrapAndApplyHeader(reply, 0, headerEncoder)
                .correlationId(stateQueryDecoder.correlationId())
                .applied(machine.applied())
                .duplicates(machine.duplicates())
                .stale(machine.stale())
                .rejected(machine.rejected())
                .activeSessions(machine.store().activeCount())
                .stoppedSessions(machine.store().stoppedCount())
                .stateDigest(machine.digest())
                .stateVersion(AccountingStateMachine.STATE_VERSION)
                .activeVersion(machine.versions().active())
                .lowestSupportedVersion(machine.versions().lowestSupported());
        if (session != null) {
            egress.send(session, reply, MessageHeaderEncoder.ENCODED_LENGTH + stateReportEncoder.encodedLength());
        }
    }

    /** One session by its key. */
    void session(ClientSession session, DirectBuffer buffer, int offset, MessageHeaderDecoder header) {
        sessionQueryDecoder.wrapAndApplyHeader(buffer, offset, header);
        SessionStore store = machine.store();
        int slot = store.find(sessionQueryDecoder.sessionKeyHi(), sessionQueryDecoder.sessionKeyLo());
        sessionReportEncoder
                .wrapAndApplyHeader(reply, 0, headerEncoder)
                .correlationId(sessionQueryDecoder.correlationId());
        if (slot < 0) {
            sessionReportEncoder
                    .status(SessionStatus.UNKNOWN)
                    .nasId(0)
                    .statusType(0)
                    .sessionTime(0)
                    .eventTimestamp(0)
                    .inputOctets(0)
                    .outputOctets(0);
        } else {
            sessionReportEncoder
                    .status(store.state(slot) == SessionStore.ACTIVE ? SessionStatus.ACTIVE : SessionStatus.STOPPED)
                    .nasId(store.nasId(slot))
                    .statusType(store.statusType(slot))
                    .sessionTime(store.sessionTime(slot))
                    .eventTimestamp(store.eventTimestamp(slot))
                    .inputOctets(store.inputOctets(slot))
                    .outputOctets(store.outputOctets(slot));
        }
        int identity = slot < 0 ? 0 : store.identity(slot, identityScratch, 0);
        sessionReportEncoder.putIdentity(identityScratch, 0, identity);
        if (session != null) {
            egress.send(session, reply, MessageHeaderEncoder.ENCODED_LENGTH + sessionReportEncoder.encodedLength());
        }
    }

    /**
     * The active sessions of a user, at most {@link #MAX_LISTED} (ADR 0036). A scan of the store: an operator's or a
     * Simultaneous-Use question, not one per accounting packet.
     */
    void userSessions(ClientSession session, DirectBuffer buffer, int offset, MessageHeaderDecoder header) {
        userSessionsQueryDecoder.wrapAndApplyHeader(buffer, offset, header);
        long user = userSessionsQueryDecoder.userKey();
        SessionStore store = machine.store();
        int count = 0;
        for (int slot = 0, n = store.highWater(); slot < n && count < MAX_LISTED; slot++) {
            if (user != 0 && store.state(slot) == SessionStore.ACTIVE && store.userKey(slot) == user) {
                count++;
            }
        }
        io.radiusward.protocol.UserSessionsReportEncoder.SessionsEncoder sessions = userSessionsReportEncoder
                .wrapAndApplyHeader(listBuffer, 0, headerEncoder)
                .correlationId(userSessionsQueryDecoder.correlationId())
                .sessionsCount(count);
        for (int slot = 0, n = store.highWater(), written = 0; slot < n && written < count; slot++) {
            if (store.state(slot) == SessionStore.ACTIVE && store.userKey(slot) == user) {
                int length = store.identity(slot, identityScratch, 0);
                sessions.next()
                        .keyHi(store.keyHi(slot))
                        .keyLo(store.keyLo(slot))
                        .nasId(store.nasId(slot))
                        .firstSeen(store.firstSeen(slot))
                        .lastSeen(store.lastSeen(slot))
                        .putIdentity(identityScratch, 0, length);
                written++;
            }
        }
        if (session != null) {
            egress.send(
                    session,
                    listBuffer,
                    MessageHeaderEncoder.ENCODED_LENGTH + userSessionsReportEncoder.encodedLength());
        }
    }

    /** A page of active sessions with a user, from a slot on (the gateways' store sweep, ADR 0036). */
    void sessionPage(ClientSession session, DirectBuffer buffer, int offset, MessageHeaderDecoder header) {
        sessionPageQueryDecoder.wrapAndApplyHeader(buffer, offset, header);
        SessionStore store = machine.store();
        int limit = Math.max(1, Math.min(MAX_LISTED, sessionPageQueryDecoder.maxSessions()));
        int from = Math.max(0, sessionPageQueryDecoder.fromSlot());
        int n = store.highWater();
        int count = 0;
        int slot = from;
        for (; slot < n && count < limit; slot++) {
            if (store.state(slot) == SessionStore.ACTIVE && store.userKey(slot) != 0) {
                count++;
            }
        }
        io.radiusward.protocol.SessionPageReportEncoder.SessionsEncoder sessions = sessionPageReportEncoder
                .wrapAndApplyHeader(listBuffer, 0, headerEncoder)
                .correlationId(sessionPageQueryDecoder.correlationId())
                .nextSlot(slot >= n ? -1 : slot)
                .sessionsCount(count);
        for (int s = from, written = 0; written < count; s++) {
            if (store.state(s) == SessionStore.ACTIVE && store.userKey(s) != 0) {
                int length = store.identity(s, identityScratch, 0);
                sessions.next()
                        .keyHi(store.keyHi(s))
                        .keyLo(store.keyLo(s))
                        .nasId(store.nasId(s))
                        .userKey(store.userKey(s))
                        .putIdentity(identityScratch, 0, length);
                written++;
            }
        }
        if (session != null) {
            egress.send(
                    session,
                    listBuffer,
                    MessageHeaderEncoder.ENCODED_LENGTH + sessionPageReportEncoder.encodedLength());
        }
    }
}
