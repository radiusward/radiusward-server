/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import java.util.UUID;

/**
 * One accounting event the cluster applied (or recognised as stale), as exported. Duplicates and rejected
 * events are never exported.
 *
 * @param eventId the 128-bit exact key: identical for every retransmission of the event
 * @param logPosition position of the entry in the replicated log
 * @param commitTime cluster time of the entry (ms since the epoch); identical on every replay
 * @param sessionKey 128-bit session key, {@code null} for NAS-wide events (Accounting-On/Off)
 * @param sessionTime {@code Acct-Session-Time} in seconds, {@code null} when absent
 * @param eventTimestamp {@code Event-Timestamp} in seconds, {@code null} when absent
 * @param nasId the configured NAS entry ({@code nas.<name>.id})
 * @param rawAttributes the attribute section of the original request
 * @param nasDevice the device behind the NAS entry (ADR 0019): its normalised identity, {@code null} when the entry
 *     identifies devices by source address only or the request carried no identity
 */
public record ExportEvent(
        UUID eventId,
        long logPosition,
        long commitTime,
        int nasId,
        int gatewayId,
        UUID sessionKey,
        String acctSessionId,
        int statusType,
        EventOutcome outcome,
        Long sessionTime,
        Long eventTimestamp,
        long inputOctets,
        long outputOctets,
        byte[] rawAttributes,
        String nasDevice) {

    /** An event without a device identity. */
    public ExportEvent(
            UUID eventId,
            long logPosition,
            long commitTime,
            int nasId,
            int gatewayId,
            UUID sessionKey,
            String acctSessionId,
            int statusType,
            EventOutcome outcome,
            Long sessionTime,
            Long eventTimestamp,
            long inputOctets,
            long outputOctets,
            byte[] rawAttributes) {
        this(
                eventId,
                logPosition,
                commitTime,
                nasId,
                gatewayId,
                sessionKey,
                acctSessionId,
                statusType,
                outcome,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                rawAttributes,
                null);
    }

    /** How the cluster's state machine treated the event. */
    public enum EventOutcome {
        APPLIED,
        /** older than the session's stored progress; kept as history, did not change the session */
        STALE,
        /** a Start that arrived after the session's Interim: completed the session (start time), kept its progress */
        MERGED
    }
}
