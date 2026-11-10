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
         * credential verifier), or, for a proxied realm, by its home server (ADR 0044).
         *
         * @param exchange the challenges and the response, as a home server needs them
         */
        Inner msChapV2(String user, MsChapV2 exchange);

        /** A password inside a tunnel (TTLS/PAP), checked like PAP outside it (stored formats or a verifier). */
        Inner password(String user, byte[] password);

        /**
         * CHAP inside a tunnel (TTLS/CHAP, and EAP-MD5 inside TTLS, which is the same computation): MD5 of the
         * identifier, the cleartext password and the challenge; only for stores that allow CHAP (cleartext).
         */
        default Inner chap(String user, int identifier, byte[] challenge, byte[] response) {
            return new Inner(AccessHandler.REJECT, null);
        }

        /** MS-CHAPv1 inside a tunnel (TTLS/MS-CHAP): the NT response to an 8-byte challenge, checked as outside. */
        default Inner msChapV1(String user, byte[] challenge, byte[] ntResponse) {
            return new Inner(AccessHandler.REJECT, null);
        }

        /** A SIM subscriber's check items (its keys), looked up by IMSI in the stores (ADR 0061). */
        default Subscriber subscriber(String imsi) {
            return new Subscriber(AccessHandler.REJECT, List.of());
        }

        /** The subscriber's next EAP-AKA sequence number from the cluster; see {@link SessionLimits#nextSqn}. */
        default long nextSqn(String imsi, long floor) {
            return SessionLimits.SQN_UNAVAILABLE;
        }
    }

    /**
     * A SIM subscriber's store entry: {@link AccessHandler#ACCEPT} with its check items, {@link AccessHandler#REJECT}
     * when no store knows it, {@link AccessHandler#DROP} when a store is unreachable.
     */
    record Subscriber(int code, List<AttributeItem> checks) {}

    /**
     * The answer of an inner check: {@link AccessHandler#ACCEPT} with the MS-CHAP session key (MD4 of the NT hash),
     * {@link AccessHandler#REJECT}, or {@link AccessHandler#DROP} when it cannot tell.
     */
    record Inner(int code, byte[] ntHashHash, String success, byte[] sendKey, byte[] receiveKey) {

        Inner(int code, byte[] ntHashHash) {
            this(code, ntHashHash, null, null, null);
        }

        /**
         * An MS-CHAPv2 acceptance by a home server (ADR 0044): its authenticator response ({@code S=...}) and the
         * server's MPPE send and receive keys, instead of the NT hash's MD4.
         */
        static Inner proxied(String success, byte[] sendKey, byte[] receiveKey) {
            return new Inner(AccessHandler.ACCEPT, null, success, sendKey, receiveKey);
        }

        /** Whether an MS-CHAPv2 acceptance carries what the tunnel needs: a key, or the home server's answer. */
        boolean keyed() {
            return ntHashHash != null || (success != null && sendKey != null && receiveKey != null);
        }

        /** The authenticator response ({@code S=} and 40 hex digits) for the peer. */
        String authenticatorResponse(byte[] ntResponse, byte[] challengeHash) {
            return success != null
                    ? success
                    : MsChap.authenticatorResponseFromKey(ntHashHash, ntResponse, challengeHash);
        }

        /** The server's MPPE send ({@code send}) or receive key (RFC 3079), 16 bytes. */
        byte[] serverKey(byte[] ntResponse, boolean send) {
            if (ntHashHash == null) {
                return send ? sendKey : receiveKey;
            }
            return MsChap.serverKey(MsChap.masterKeyFromKey(ntHashHash, ntResponse), send);
        }
    }

    /**
     * An MS-CHAPv2 exchange inside a tunnel.
     *
     * @param challengeHash the RFC 2759 challenge hash the NT response answers
     * @param authenticatorChallenge the server's 16-byte challenge
     * @param peerChallenge the peer's 16-byte challenge
     * @param ident the MS-CHAPv2 identifier
     */
    record MsChapV2(
            byte[] challengeHash, byte[] ntResponse, byte[] authenticatorChallenge, byte[] peerChallenge, int ident) {}

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

        static final Step STORE_UNAVAILABLE = new Step(null, false, null, true);

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
