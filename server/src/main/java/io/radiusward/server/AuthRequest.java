/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.radius.codec.AccessRequests;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The Access-Request a worker is deciding and what its checks leave for the reply: the MS-CHAP result, the EAP round,
 * the PAP password TOTP's append mode left. Passed to every check explicitly; one per worker, reset by {@link #begin}
 * for each request, so nothing is allocated per request. The worker's caches that outlive a request are {@link
 * #caches()}.
 */
final class AuthRequest {

    private final StoreAccessHandler.WorkerCache caches;
    private AccessContext context;
    private AccessPolicies policies = AccessPolicies.NONE;
    final MsChapOutcome msChap = new MsChapOutcome();
    final EapRound eap = new EapRound();
    /** What TOTP's append mode left of the PAP password (ADR 0053); {@code null}: the User-Password. */
    private byte[] papRemainder;

    AuthRequest(StoreAccessHandler.WorkerCache caches) {
        this.caches = caches;
    }

    /**
     * Starts deciding {@code request} under {@code policies}: the previous request's results are forgotten. The
     * request keeps these policies to the end, whatever a reload sets meanwhile.
     */
    AuthRequest begin(AccessContext request, AccessPolicies policies) {
        this.context = request;
        this.policies = policies;
        msChap.reset();
        eap.reset();
        return this;
    }

    /** The request is decided: the PAP password is wiped. */
    void end() {
        if (papRemainder != null) {
            Arrays.fill(papRemainder, (byte) 0);
            papRemainder = null;
        }
    }

    /**
     * The PAP password, a copy the caller wipes: the decrypted User-Password, or what TOTP's append mode left of it;
     * {@code null}: none.
     */
    byte[] papPassword() {
        if (papRemainder != null) {
            return papRemainder.clone();
        }
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
        int n = context.credentials()
                .decryptUserPassword(context.request(), context.nas().secret(), buffer, 0);
        if (n < 0) {
            return null;
        }
        byte[] password = Arrays.copyOf(buffer.byteArray(), n);
        Arrays.fill(buffer.byteArray(), (byte) 0);
        return password;
    }

    /** TOTP's append mode took the code off the end: {@code rest} is the password to check (wiped by {@link #end}). */
    void papRemainder(byte[] rest) {
        papRemainder = rest;
    }

    AccessContext context() {
        return context;
    }

    /** The policies this request is decided under. */
    AccessPolicies policies() {
        return policies;
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
