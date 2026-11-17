/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.util.Arrays;

/**
 * The Access-Request a worker is deciding and what its checks leave for the reply: the MS-CHAP result, the EAP round,
 * the PAP password TOTP's append mode left. Passed to every check explicitly; one per worker, reset by {@link #begin}
 * for each request, so nothing is allocated per request. The worker's caches that outlive a request are {@link
 * #caches()}.
 */
final class AuthRequest {

    private final StoreAccessHandler.WorkerCache caches;
    private AccessContext context;
    final MsChapOutcome msChap = new MsChapOutcome();
    final EapRound eap = new EapRound();
    /** What TOTP's append mode left of the PAP password (ADR 0053); {@code null}: the User-Password. */
    byte[] papPassword;

    AuthRequest(StoreAccessHandler.WorkerCache caches) {
        this.caches = caches;
    }

    /** Starts deciding {@code request}: the previous request's results are forgotten. */
    AuthRequest begin(AccessContext request) {
        this.context = request;
        msChap.reset();
        eap.reset();
        return this;
    }

    /** The request is decided: the PAP password is wiped. */
    void end() {
        if (papPassword != null) {
            Arrays.fill(papPassword, (byte) 0);
            papPassword = null;
        }
    }

    AccessContext context() {
        return context;
    }

    StoreAccessHandler.WorkerCache caches() {
        return caches;
    }

    /** The EAP state of the request: its packet, conversation, State and the method's MSK. */
    static final class EapRound {
        EapPacket packet;
        EapConversations.Conversation conversation;
        byte[] state;
        byte[] msk;

        void reset() {
            packet = null;
            state = null;
            conversation = null;
            msk = null;
        }
    }

    /** What a successful MS-CHAP check leaves for the reply. */
    static final class MsChapOutcome {
        boolean success;
        int ident;
        byte[] ntHashHash;
        byte[] ntResponse;
        byte[] challengeHash;

        void reset() {
            success = false;
            ntHashHash = null;
            ntResponse = null;
            challengeHash = null;
        }
    }
}
