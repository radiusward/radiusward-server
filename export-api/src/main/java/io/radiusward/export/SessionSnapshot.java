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
 * @param startedAt commit time of the Start (ms), {@code null} when this change does not know it
 * @param stoppedAt commit time of the change that closed the session, {@code null} while active
 * @param rawAttributes attributes of the event behind the change, {@code null} for closures
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
        byte[] rawAttributes) {

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
