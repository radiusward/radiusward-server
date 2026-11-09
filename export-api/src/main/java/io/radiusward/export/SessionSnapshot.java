/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import java.util.UUID;

/**
 * A session as the cluster holds it after a change. Sinks store it only if {@code projectionVersion} is newer
 * than what they hold ("update only if newer"), so replays and out-of-order batches never move it back.
 *
 * @param projectionVersion log position of the change; increases with every change of the session
 * @param acctSessionId {@code null} when the change had no event of its own (closed by NAS restart or timeout)
 * @param startedAt start of the session (ms): the Start's Event-Timestamp (its commit time without one); for a
 *     session first seen by an Interim or Stop, that event's time minus its Acct-Session-Time until a late Start
 *     with an Event-Timestamp replaces it. {@code null} when this change does not know it: a sink keeps its stored
 *     value then, and replaces it otherwise
 * @param stoppedAt commit time of the change that closed the session, {@code null} while active
 * @param rawAttributes attributes of the event behind the change, {@code null} for closures
 * @param nasId the configured NAS entry; it never changes for a session (sinks keep the first one). A closure
 *     without an event of its own (NAS restart, idle timeout) of a device behind NAT carries the device's scope
 *     instead, since the replicated state keeps only that
 * @param nasDevice the device behind the NAS entry (ADR 0019), {@code null} when not known to this change: a sink
 *     keeps its stored value then
 */
public record SessionSnapshot(
        UUID sessionKey,
        long projectionVersion,
        int nasId,
        String acctSessionId,
        State state,
        CloseCause closeCause,
        int statusType,
        Long sessionTime,
        long inputOctets,
        long outputOctets,
        long lastReceivedAt,
        Long startedAt,
        Long stoppedAt,
        byte[] rawAttributes,
        String nasDevice) {

    /** A snapshot without a device identity. */
    public SessionSnapshot(
            UUID sessionKey,
            long projectionVersion,
            int nasId,
            String acctSessionId,
            State state,
            CloseCause closeCause,
            int statusType,
            Long sessionTime,
            long inputOctets,
            long outputOctets,
            long lastReceivedAt,
            Long startedAt,
            Long stoppedAt,
            byte[] rawAttributes) {
        this(
                sessionKey,
                projectionVersion,
                nasId,
                acctSessionId,
                state,
                closeCause,
                statusType,
                sessionTime,
                inputOctets,
                outputOctets,
                lastReceivedAt,
                startedAt,
                stoppedAt,
                rawAttributes,
                null);
    }

    public enum State {
        ACTIVE,
        STOPPED
    }

    public enum CloseCause {
        NONE,
        /** Acct-Status-Type Stop */
        STOP,
        /** Accounting-On/Off of the NAS */
        NAS_RESTART,
        /** no event for the idle timeout (lost Stop) */
        IDLE_TIMEOUT
    }
}
