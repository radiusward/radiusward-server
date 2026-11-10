/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.gateway.EapMethod.Credentials;
import io.radiusward.gateway.EapMethod.Inner;
import io.radiusward.gateway.EapMethod.Step;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * An EAP conversation inside a tunnel with whole EAP packets (TTLS, RFC 5281 §11.2.4; ADR 0040): the peer's
 * Identity response, then an inner method from the configured list (the peer may Nak to another) — EAP-MD5 (checked
 * like CHAP: cleartext of a store that allows it), EAP-MSCHAPv2 (as outside, ends with a Success request the peer
 * acknowledges) or EAP-GTC (a password, checked like PAP). Each step returns the next inner request
 * ({@link Step#request()}: a whole EAP packet), success, failure, or unavailable (the inner check could not be made;
 * {@link #retry} repeats it for the peer's retransmission). The tunnel's keys are the method's keys: inner keys are not
 * used.
 */
final class InnerEap {

    static final int MD5 = EapPacket.TYPE_MD5;
    static final int GTC = 6;
    static final int MS_CHAP_V2 = 26;
    private static final byte[] GTC_PROMPT = "Password: ".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SERVER_NAME = "radiusward".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        IDENTITY,
        METHOD,
        MS_CHAP_SUCCESS
    }

    private final List<Integer> types;
    private State state = State.IDENTITY;
    private int type;
    private int identifier = RANDOM.nextInt(256);
    private int msChapId;
    private boolean begun;
    private final byte[] challenge = new byte[16];
    private String identity;
    private byte[] pending; // the last response, when its check could not be made

    /** @param types the inner EAP types offered, first preferred (MD5, MS-CHAPv2, GTC) */
    InnerEap(List<Integer> types) {
        this.types = List.copyOf(types);
    }

    /** The inner identity, once the peer sent it. */
    String identity() {
        return identity;
    }

    /** The peer's next inner EAP packet. */
    Step handle(byte[] packet, Credentials credentials) {
        EapPacket p = EapPacket.parse(packet);
        if (p == null || p.code() != EapPacket.RESPONSE) {
            return Step.FAILED;
        }
        if (state == State.IDENTITY) {
            if (p.type() != EapPacket.TYPE_IDENTITY) {
                return Step.FAILED;
            }
            identity = new String(p.data(), StandardCharsets.UTF_8).trim();
            identifier = p.identifier();
            return identity.isEmpty() ? Step.FAILED : start(types.get(0));
        }
        if (p.identifier() != identifier) {
            return Step.FAILED; // answers no request of ours
        }
        if (state == State.MS_CHAP_SUCCESS) {
            // the peer acknowledges our Success request: opcode 3 alone
            return p.type() == MS_CHAP_V2 && p.data().length >= 1 && p.data()[0] == 3
                    ? Step.succeeded(null)
                    : Step.FAILED;
        }
        if (!begun && p.type() == EapPacket.TYPE_NAK) {
            for (byte wanted : p.data()) {
                if ((wanted & 0xFF) != type && types.contains(wanted & 0xFF)) {
                    return start(wanted & 0xFF);
                }
            }
            return Step.FAILED; // nothing both sides support
        }
        if (p.type() != type) {
            return Step.FAILED;
        }
        begun = true;
        return check(p.data(), credentials);
    }

    /** The check of the last response again, after it was unavailable. */
    Step retry(Credentials credentials) {
        return pending == null ? Step.FAILED : check(pending, credentials);
    }

    private Step check(byte[] data, Credentials credentials) {
        if (credentials.inner() == null) {
            return Step.FAILED;
        }
        return switch (type) {
            case MD5 -> md5(data, credentials);
            case GTC -> gtc(data, credentials);
            default -> msChapV2(data, credentials);
        };
    }

    /** EAP-MD5: value size 16, the MD5 of identifier, password and challenge (RFC 3748 §5.4). */
    private Step md5(byte[] data, Credentials credentials) {
        if (data.length < 17 || data[0] != 16) {
            return Step.FAILED;
        }
        return decided(
                credentials.inner().chap(identity, identifier, challenge, Arrays.copyOfRange(data, 1, 17)), data);
    }

    /** EAP-GTC: the response is the password. */
    private Step gtc(byte[] data, Credentials credentials) {
        return data.length == 0 ? Step.FAILED : decided(credentials.inner().password(identity, data), data);
    }

    /**
     * EAP-MSCHAPv2 response: opcode 2, id, MS-length, value size 49, peer challenge 16, reserved 8, NT response 24,
     * flags, name.
     */
    private Step msChapV2(byte[] data, Credentials credentials) {
        if (data.length < 4 + 1 + 49 || data[0] != 2 || (data[1] & 0xFF) != msChapId || (data[4] & 0xFF) != 49) {
            return Step.FAILED;
        }
        byte[] peerChallenge = Arrays.copyOfRange(data, 5, 21);
        byte[] ntResponse = Arrays.copyOfRange(data, 29, 53);
        byte[] name = Arrays.copyOfRange(data, 54, data.length);
        byte[] hash = MsChap.challengeHash(peerChallenge, challenge, MsChap.v2UserName(name));
        Inner checked = credentials.inner().msChapV2(identity, hash, ntResponse);
        if (checked.code() == AccessHandler.DROP) {
            pending = data;
            return Step.UNAVAILABLE;
        }
        pending = null;
        if (checked.code() != AccessHandler.ACCEPT || checked.ntHashHash() == null) {
            return Step.FAILED;
        }
        String success = MsChap.authenticatorResponseFromKey(checked.ntHashHash(), ntResponse, hash)
                + " M=Authentication succeeded";
        state = State.MS_CHAP_SUCCESS;
        return request(MS_CHAP_V2, msChap(3, success.getBytes(StandardCharsets.US_ASCII)));
    }

    private Step decided(Inner checked, byte[] data) {
        if (checked.code() == AccessHandler.DROP) {
            pending = data;
            return Step.UNAVAILABLE;
        }
        pending = null;
        return checked.code() == AccessHandler.ACCEPT ? Step.succeeded(null) : Step.FAILED;
    }

    /** The first request of an inner method. */
    private Step start(int offered) {
        type = offered;
        begun = false;
        state = State.METHOD;
        RANDOM.nextBytes(challenge);
        return switch (offered) {
            case MD5 -> {
                byte[] d = new byte[1 + 16 + SERVER_NAME.length];
                d[0] = 16;
                System.arraycopy(challenge, 0, d, 1, 16);
                System.arraycopy(SERVER_NAME, 0, d, 17, SERVER_NAME.length);
                yield request(MD5, d);
            }
            case GTC -> request(GTC, GTC_PROMPT);
            default -> {
                msChapId = RANDOM.nextInt(256);
                byte[] body = new byte[1 + 16 + SERVER_NAME.length];
                body[0] = 16;
                System.arraycopy(challenge, 0, body, 1, 16);
                System.arraycopy(SERVER_NAME, 0, body, 17, SERVER_NAME.length);
                yield request(MS_CHAP_V2, msChap(1, body));
            }
        };
    }

    private Step request(int requestType, byte[] data) {
        identifier = (identifier + 1) & 0xFF;
        return Step.next(EapPacket.request(identifier, requestType, data).encode());
    }

    /** EAP-MSCHAPv2 type data: opcode, id, MS-length, body. */
    private byte[] msChap(int opcode, byte[] body) {
        int msLength = 4 + body.length;
        byte[] m = new byte[msLength];
        m[0] = (byte) opcode;
        m[1] = (byte) msChapId;
        m[2] = (byte) (msLength >>> 8);
        m[3] = (byte) msLength;
        System.arraycopy(body, 0, m, 4, body.length);
        return m;
    }
}
