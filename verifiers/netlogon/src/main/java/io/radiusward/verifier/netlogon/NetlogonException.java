/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.io.IOException;

/** A Netlogon call answered with an error NTSTATUS. */
final class NetlogonException extends IOException {

    static final long STATUS_ACCESS_DENIED = 0xC0000022L;
    static final long STATUS_NO_TRUST_SAM_ACCOUNT = 0xC000018BL;
    static final long STATUS_WRONG_PASSWORD = 0xC000006AL;
    static final long STATUS_NO_SUCH_USER = 0xC0000064L;
    static final long STATUS_LOGON_FAILURE = 0xC000006DL;
    static final long STATUS_ACCOUNT_DISABLED = 0xC0000072L;

    final long status;

    NetlogonException(long status, String call) {
        super(String.format("%s: NTSTATUS 0x%08X", call, status));
        this.status = status;
    }

    static void check(long status, String call) throws NetlogonException {
        if (status != 0) {
            throw new NetlogonException(status, call);
        }
    }
}
