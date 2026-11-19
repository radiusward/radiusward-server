/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import io.radiusward.protocol.SessionStatus;
import io.radiusward.tools.admin.AdminClient;
import java.time.Duration;

/**
 * An accounting session as the cluster holds it: committed by the member, the same state every member would have.
 *
 * @param nas the NAS entry it came from
 * @param acctSessionId its Acct-Session-Id
 * @param user its User-Name ({@code null} if the NAS sent none)
 * @param active whether it is open (no Stop yet, not timed out)
 * @param statusType the Acct-Status-Type last applied (1 Start, 2 Stop, 3 Interim-Update)
 * @param sessionTime Acct-Session-Time of the last event applied
 * @param inputOctets input octets with Gigawords
 * @param outputOctets output octets with Gigawords
 */
public record Session(
        String nas,
        String acctSessionId,
        String user,
        boolean active,
        int statusType,
        Duration sessionTime,
        long inputOctets,
        long outputOctets) {

    /** An open session in a user's list. */
    public record Active(String nas, String acctSessionId, String user) {}

    static Session of(String nas, String acctSessionId, AdminClient.Session s) {
        if (s == null || s.status() == SessionStatus.UNKNOWN || s.status() == SessionStatus.NULL_VAL) {
            return null;
        }
        return new Session(
                nas,
                acctSessionId,
                s.attribute(1),
                s.status() == SessionStatus.ACTIVE,
                (int) s.statusType(),
                Duration.ofSeconds(s.sessionTime()),
                s.inputOctets(),
                s.outputOctets());
    }
}
