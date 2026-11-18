/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import org.agrona.DirectBuffer;

/**
 * Events for the state machine's tests, with what an older protocol version did not carry left out: the idle timeout
 * (0: the default), the user and device (0: none), the identifying attributes (none). The log applier always passes
 * all of them.
 */
final class MachineEvents {

    private MachineEvents() {}

    static int apply(
            AccountingStateMachine machine,
            long sessionHi,
            long sessionLo,
            long exactHi,
            long exactLo,
            int nasId,
            int statusType,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            long now) {
        return apply(
                machine,
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                0,
                now);
    }

    /** @param idleMinutes the NAS entry's idle timeout, 0: the default */
    static int apply(
            AccountingStateMachine machine,
            long sessionHi,
            long sessionLo,
            long exactHi,
            long exactLo,
            int nasId,
            int statusType,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            int idleMinutes,
            long now) {
        return apply(
                machine,
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                idleMinutes,
                0,
                0,
                now);
    }

    /** @param userKey hash of the User-Name, 0: none; {@code deviceKey} the Calling-Station-Id's, 0: none */
    static int apply(
            AccountingStateMachine machine,
            long sessionHi,
            long sessionLo,
            long exactHi,
            long exactLo,
            int nasId,
            int statusType,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            int idleMinutes,
            long userKey,
            long deviceKey,
            long now) {
        return machine.apply(
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                idleMinutes,
                userKey,
                deviceKey,
                null,
                0,
                0,
                now);
    }

    static int apply(
            AccountingStateMachine machine,
            long sessionHi,
            long sessionLo,
            long exactHi,
            long exactLo,
            int nasId,
            int statusType,
            int flags,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            int idleMinutes,
            long userKey,
            long deviceKey,
            DirectBuffer identity,
            int identityOffset,
            int identityLength,
            long now) {
        return machine.apply(
                sessionHi,
                sessionLo,
                exactHi,
                exactLo,
                nasId,
                statusType,
                flags,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                idleMinutes,
                userKey,
                deviceKey,
                identity,
                identityOffset,
                identityLength,
                now);
    }
}
