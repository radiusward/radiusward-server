/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;

/**
 * PEAPv0 with EAP-MSCHAPv2 inside (MS-PEAP, ADR 0029): a TLS tunnel that authenticates only the server, then inside it
 * the real identity and an MS-CHAPv2 exchange, checked by the gateway like MS-CHAPv2 outside (local NT hash, cleartext
 * opt-in, a credential verifier such as Netlogon). Inner EAP messages go without their header (type and data only),
 * except the closing Result TLV, which carries it. Keys come from the tunnel (label {@code client EAP encryption},
 * TLS 1.3: RFC 9427).
 *
 * <p>Inner steps: Identity request → identity; MS-CHAPv2 Challenge → Response, checked; Success request → Success
 * response; Result TLV success → the peer's Result TLV → EAP-Success. A wrong credential: MS-CHAPv2 Failure request →
 * the peer's Failure response → Result TLV failure → EAP-Failure.
 */
final class Peap extends TlsTunnel {

    static final int TYPE = 25;
    static final int MS_CHAP_V2 = 26;
    static final int TLV = 33;
    private static final int OP_CHALLENGE = 1;
    private static final int OP_RESPONSE = 2;
    private static final int OP_SUCCESS = 3;
    private static final int OP_FAILURE = 4;
    private static final byte[] SERVER_NAME = "radiusward".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        HANDSHAKE,
        IDENTITY,
        CHALLENGE,
        SUCCESS,
        FAILURE,
        RESULT_OK,
        RESULT_FAILED
    }

    private State state = State.HANDSHAKE;
    private final byte[] authenticatorChallenge = new byte[16];
    private int msChapId;
    private int innerId;
    private String identity;
    private String authenticated;
    private byte[] pendingHash; // an inner check that could not be answered, for the retransmission
    private byte[] pendingResponse;

    Peap(EapTlsConfig config) {
        super(config);
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    boolean clientCertificate() {
        return false;
    }

    @Override
    String keyLabel() {
        return "client EAP encryption";
    }

    @Override
    public String innerIdentity() {
        return authenticated;
    }

    @Override
    byte[] onFinished(boolean tls13) {
        if (!tls13) {
            return null; // TLS 1.2: the peer acknowledges our Finished first
        }
        state = State.IDENTITY;
        return new byte[] {EapPacket.TYPE_IDENTITY};
    }

    @Override
    Step onAck(Credentials credentials) {
        if (state != State.HANDSHAKE) {
            return Step.FAILED;
        }
        state = State.IDENTITY;
        return sendApplication(new byte[] {EapPacket.TYPE_IDENTITY});
    }

    @Override
    Step onData(byte[] data, Credentials credentials) {
        if (data.length < 1) {
            return Step.FAILED;
        }
        return switch (state) {
            case IDENTITY -> identity(data);
            case CHALLENGE -> response(data, credentials);
            case SUCCESS ->
                data.length >= 2 && (data[0] & 0xFF) == MS_CHAP_V2 && data[1] == OP_SUCCESS
                        ? result(true)
                        : Step.FAILED;
            case FAILURE -> result(false);
            case RESULT_OK -> resultAnswered(data) ? Step.succeeded(msk()) : Step.FAILED;
            default -> Step.FAILED;
        };
    }

    private Step identity(byte[] data) {
        if ((data[0] & 0xFF) != EapPacket.TYPE_IDENTITY || data.length < 2) {
            return Step.FAILED; // a Nak or anything else: only EAP-MSCHAPv2 is offered inside
        }
        identity = new String(data, 1, data.length - 1, StandardCharsets.UTF_8).trim();
        if (identity.isEmpty()) {
            return Step.FAILED;
        }
        RANDOM.nextBytes(authenticatorChallenge);
        msChapId = RANDOM.nextInt(256);
        state = State.CHALLENGE;
        byte[] body = new byte[1 + 16 + SERVER_NAME.length];
        body[0] = 16;
        System.arraycopy(authenticatorChallenge, 0, body, 1, 16);
        System.arraycopy(SERVER_NAME, 0, body, 17, SERVER_NAME.length);
        return sendApplication(msChap(OP_CHALLENGE, body));
    }

    private Step response(byte[] data, Credentials credentials) {
        // type, opcode, id, ms-length(2), value-size 49, peer challenge 16, reserved 8, NT response 24, flags, name
        if (data.length < 5 + 1 + 49
                || (data[0] & 0xFF) != MS_CHAP_V2
                || data[1] != OP_RESPONSE
                || (data[5] & 0xFF) != 49) {
            return Step.FAILED;
        }
        byte[] peerChallenge = Arrays.copyOfRange(data, 6, 22);
        byte[] ntResponse = Arrays.copyOfRange(data, 30, 54);
        byte[] name = Arrays.copyOfRange(data, 55, data.length);
        byte[] challengeHash = MsChap.challengeHash(peerChallenge, authenticatorChallenge, MsChap.v2UserName(name));
        return check(challengeHash, ntResponse, credentials);
    }

    @Override
    Step onRetry(Credentials credentials) {
        return pendingHash == null ? Step.FAILED : check(pendingHash, pendingResponse, credentials);
    }

    /** The inner MS-CHAPv2 check by the gateway; its outcome as Success or Failure inside the tunnel. */
    private Step check(byte[] challengeHash, byte[] ntResponse, Credentials credentials) {
        if (credentials.inner() == null) {
            return Step.FAILED;
        }
        Inner checked = credentials.inner().msChapV2(identity, challengeHash, ntResponse);
        if (checked.code() == AccessHandler.DROP) {
            pendingHash = challengeHash;
            pendingResponse = ntResponse;
            return Step.UNAVAILABLE;
        }
        pendingHash = null;
        pendingResponse = null;
        if (checked.code() != AccessHandler.ACCEPT || checked.ntHashHash() == null) {
            state = State.FAILURE;
            String failure = "E=691 R=0 C="
                    + HexFormat.of().formatHex(authenticatorChallenge).toUpperCase(Locale.ROOT)
                    + " V=3 M=Authentication failed";
            return sendApplication(msChap(OP_FAILURE, failure.getBytes(StandardCharsets.US_ASCII)));
        }
        authenticated = identity;
        state = State.SUCCESS;
        String success = MsChap.authenticatorResponseFromKey(checked.ntHashHash(), ntResponse, challengeHash)
                + " M=Authentication succeeded";
        return sendApplication(msChap(OP_SUCCESS, success.getBytes(StandardCharsets.US_ASCII)));
    }

    /** Result TLV (MS-PEAP §2.2.8.1): with the EAP header, type 33, mandatory TLV 3, value 1 success / 2 failure. */
    private Step result(boolean success) {
        state = success ? State.RESULT_OK : State.RESULT_FAILED;
        if (!success) {
            authenticated = null;
        }
        innerId = (innerId + 1) & 0xFF;
        byte[] p = {
            EapPacket.REQUEST,
            (byte) innerId,
            0,
            11,
            (byte) TLV,
            (byte) 0x80,
            0x03,
            0x00,
            0x02,
            0x00,
            (byte) (success ? 1 : 2)
        };
        return sendApplication(p);
    }

    /** The peer's Result TLV, success. */
    private boolean resultAnswered(byte[] data) {
        EapPacket p = EapPacket.parse(data);
        return p != null
                && p.code() == EapPacket.RESPONSE
                && p.type() == TLV
                && p.data().length >= 6
                && (p.data()[0] & 0x3F) == 0x00
                && p.data()[1] == 0x03
                && p.data()[5] == 0x01;
    }

    /** An inner EAP-MSCHAPv2 message without the EAP header: type, opcode, id, MS-length, body. */
    private byte[] msChap(int opcode, byte[] body) {
        int msLength = 4 + body.length;
        byte[] m = new byte[1 + msLength];
        m[0] = (byte) MS_CHAP_V2;
        m[1] = (byte) opcode;
        m[2] = (byte) msChapId;
        m[3] = (byte) (msLength >>> 8);
        m[4] = (byte) msLength;
        System.arraycopy(body, 0, m, 5, body.length);
        return m;
    }
}
