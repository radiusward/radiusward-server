/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

/** Acct-Terminate-Cause: why a session stopped (RFC 2866 §5.10, RFC 3580 §3.32). */
public enum TerminateCause {
    USER_REQUEST(1),
    LOST_CARRIER(2),
    LOST_SERVICE(3),
    IDLE_TIMEOUT(4),
    SESSION_TIMEOUT(5),
    ADMIN_RESET(6),
    ADMIN_REBOOT(7),
    PORT_ERROR(8),
    NAS_ERROR(9),
    NAS_REQUEST(10),
    NAS_REBOOT(11),
    PORT_UNNEEDED(12),
    PORT_PREEMPTED(13),
    PORT_SUSPENDED(14),
    SERVICE_UNAVAILABLE(15),
    CALLBACK(16),
    USER_ERROR(17),
    HOST_REQUEST(18),
    SUPPLICANT_RESTART(19),
    REAUTHENTICATION_FAILURE(20),
    PORT_REINITIALIZED(21),
    PORT_ADMINISTRATIVELY_DISABLED(22);

    private final int value;

    TerminateCause(int value) {
        this.value = value;
    }

    /** The attribute's value. */
    public int value() {
        return value;
    }
}
