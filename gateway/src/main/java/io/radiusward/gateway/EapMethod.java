/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import java.util.List;

/**
 * One EAP method of one conversation (5.7, ADR 0026): started with the peer's identity, then given each response until
 * it succeeds or fails. Stateful, used by one worker at a time (the conversation table hands it out).
 */
interface EapMethod {

    /**
     * What a method may use: the outer user's check items (passwords), whether its store allows cleartext use, and —
     * for tunneled methods — the gateway's checks of an inner user's credential.
     */
    record Credentials(List<AttributeItem> passwords, boolean cleartextAllowed, InnerAuth inner) {

        Credentials(List<AttributeItem> passwords, boolean cleartextAllowed) {
            this(passwords, cleartextAllowed, null);
        }
    }

    /** The gateway's credential checks for the inner user of a tunnel (PEAP, TTLS). */
    interface InnerAuth {

        /**
         * MS-CHAPv2 inside a tunnel: the user is looked up and checked like outside it (local NT hash, cleartext opt-in,
         * credential verifier).
         *
         * @param challengeHash the RFC 2759 challenge hash the NT response answers
         */
        Inner msChapV2(String user, byte[] challengeHash, byte[] ntResponse);

        /** A password inside a tunnel (TTLS/PAP), checked like PAP outside it (stored formats or a verifier). */
        Inner password(String user, byte[] password);
    }

    /**
     * The answer of an inner check: {@link AccessHandler#ACCEPT} with the MS-CHAP session key (MD4 of the NT hash),
     * {@link AccessHandler#REJECT}, or {@link AccessHandler#DROP} when it cannot tell.
     */
    record Inner(int code, byte[] ntHashHash) {}

    /**
     * The next step: another request to the peer, success (with the MSK if the method derives one), failure, or
     * unavailable (the request is not answered and the conversation waits for the retransmission).
     */
    record Step(byte[] request, boolean success, byte[] msk, boolean unavailable) {

        static Step next(byte[] typeData) {
            return new Step(typeData, false, null, false);
        }

        static Step succeeded(byte[] msk) {
            return new Step(null, true, msk, false);
        }

        static final Step FAILED = new Step(null, false, null, false);

        static final Step UNAVAILABLE = new Step(null, false, null, true);

        boolean done() {
            return request == null;
        }
    }

    /** The EAP type number. */
    int type();

    /** The first request's type data. */
    Step start(int identifier, Credentials credentials);

    /**
     * @param identifier the identifier of the request this answers
     * @param data the response's type data
     */
    Step process(int identifier, byte[] data, Credentials credentials);

    /** For a tunneled method, the inner identity once the peer authenticated with it; {@code null} otherwise. */
    default String innerIdentity() {
        return null;
    }

    /** Whether the inner identity needs no store entry (a certificate inside the tunnel). */
    default boolean innerOptional() {
        return false;
    }
}
