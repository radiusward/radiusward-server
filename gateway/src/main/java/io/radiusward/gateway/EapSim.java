/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * EAP-SIM (RFC 4186), ADR 0061: version 1, three GSM triplets per challenge, computed with GSM-MILENAGE from the
 * subscriber's Ki and OPc, or the three triplets stored for it (weaker: the same RANDs every time). The Start round
 * offers the version and, unless the identity is a permanent one ({@code 1<IMSI>@realm}), asks for it; the peer
 * answers with its NONCE_MT. The challenge's AT_MAC covers the NONCE_MT, the response's the three SRES. The IMSI is
 * authorized afterwards, like a tunnel's inner user.
 */
final class EapSim implements EapMethod {

    static final int TYPE = 18;
    static final int START = 10;
    static final int CHALLENGE = 11;
    static final int CLIENT_ERROR = 14;
    static final int VERSION = 1;
    private static final byte[] VERSION_LIST = {0, VERSION};
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        START,
        CHALLENGE,
        DONE
    }

    private State state;
    private byte[] identity;
    private String imsi;
    private boolean identityAsked;
    private byte[] sres;
    private SimKeys.Keys keys;

    /** @param identity the EAP-Response/Identity */
    EapSim(String identity) {
        this.identity = identity == null ? new byte[0] : identity.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    public String innerIdentity() {
        return state == State.DONE ? imsi : null;
    }

    /** SIM-Start: the version list, and a request for the permanent identity unless the peer gave one. */
    @Override
    public Step start(int identifier, Credentials credentials) {
        state = State.START;
        SimMessage.Builder b = new SimMessage.Builder(START).lengthPrefixed(SimMessage.AT_VERSION_LIST, VERSION_LIST);
        if (permanentImsi(new String(identity, StandardCharsets.UTF_8)) == null) {
            identityAsked = true;
            b.add(SimMessage.AT_PERMANENT_ID_REQ, new byte[2]);
        }
        return Step.next(b.build());
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        SimMessage m = SimMessage.parse(data);
        if (m == null) {
            return Step.FAILED;
        }
        if (m.subtype() == START && state == State.START) {
            return onStart(identifier, m, credentials);
        }
        if (m.subtype() == CHALLENGE && state == State.CHALLENGE) {
            return onChallenge(identifier, data, m);
        }
        return Step.FAILED; // Client-Error, a message out of turn
    }

    /** The IMSI of a permanent EAP-SIM identity ({@code 1…}), else {@code null}. */
    static String permanentImsi(String identity) {
        if (identity.length() < 2 || identity.charAt(0) != '1') {
            return null;
        }
        int at = identity.indexOf('@');
        String imsi = identity.substring(1, at < 0 ? identity.length() : at);
        return imsi.matches("[0-9]{6,15}") ? imsi : null;
    }

    private Step onStart(int identifier, SimMessage m, Credentials credentials) {
        byte[] nonce = m.get(SimMessage.AT_NONCE_MT);
        byte[] selected = m.get(SimMessage.AT_SELECTED_VERSION);
        if (nonce == null || nonce.length != 18 || selected == null || selected.length < 2) {
            return Step.FAILED;
        }
        if (((selected[0] & 0xFF) << 8 | (selected[1] & 0xFF)) != VERSION) {
            return Step.FAILED;
        }
        byte[] given = SimMessage.lengthPrefixed(m.get(SimMessage.AT_IDENTITY));
        if (given != null) {
            identity = given;
        } else if (identityAsked) {
            return Step.FAILED; // asked for an identity and got none
        }
        String permanent = permanentImsi(new String(identity, StandardCharsets.UTF_8));
        if (permanent == null) {
            return Step.FAILED;
        }
        EapMethod.Subscriber found = credentials.inner().subscriber(permanent);
        if (found.code() == AccessHandler.DROP) {
            return Step.STORE_UNAVAILABLE;
        }
        if (found.code() != AccessHandler.ACCEPT) {
            return Step.FAILED;
        }
        SimSubscriber subscriber;
        try {
            subscriber = SimSubscriber.of(found.checks());
        } catch (IllegalArgumentException e) {
            return Step.FAILED;
        }
        Milenage.Triplet[] triplets = triplets(subscriber);
        if (triplets == null) {
            return Step.FAILED;
        }
        imsi = permanent;
        byte[] nonceMt = Arrays.copyOfRange(nonce, 2, 18);
        byte[][] kc = new byte[3][];
        byte[] rands = new byte[48];
        sres = new byte[12];
        for (int i = 0; i < 3; i++) {
            kc[i] = triplets[i].kc();
            System.arraycopy(triplets[i].rand(), 0, rands, 16 * i, 16);
            System.arraycopy(triplets[i].sres(), 0, sres, 4 * i, 4);
        }
        keys = SimKeys.fullKeys(SimKeys.simMasterKey(identity, kc, nonceMt, VERSION_LIST, VERSION));
        SimMessage.Builder b = new SimMessage.Builder(CHALLENGE)
                .reserved(SimMessage.AT_RAND, rands)
                .mac();
        byte[] data = b.build();
        byte[] mac = SimKeys.macSha1(
                keys.kAut(),
                SimMessage.packet(EapPacket.CODE_REQUEST, identifier + 1, TYPE, data, b.macOffset()),
                nonceMt);
        System.arraycopy(mac, 0, data, b.macOffset(), 16);
        state = State.CHALLENGE;
        return Step.next(data);
    }

    /** Three triplets with distinct RANDs: from GSM-MILENAGE, else the stored ones; {@code null} if neither. */
    private static Milenage.Triplet[] triplets(SimSubscriber subscriber) {
        Milenage.Triplet[] t = new Milenage.Triplet[3];
        if (subscriber.milenage()) {
            Milenage milenage = new Milenage(subscriber.ki(), subscriber.opc());
            for (int i = 0; i < 3; i++) {
                byte[] rand = new byte[16];
                RANDOM.nextBytes(rand);
                t[i] = milenage.gsm(rand);
            }
            return t;
        }
        if (subscriber.triplets().size() != 3) {
            return null;
        }
        for (int i = 0; i < 3; i++) {
            t[i] = subscriber.triplets().get(i);
            for (int j = 0; j < i; j++) {
                if (Arrays.equals(t[i].rand(), t[j].rand())) {
                    return null; // RFC 4186 §6.2: the RANDs must differ
                }
            }
        }
        return t;
    }

    private Step onChallenge(int identifier, byte[] data, SimMessage m) {
        state = State.DONE;
        if (m.macOffset() < 0) {
            imsi = null;
            return Step.FAILED;
        }
        byte[] received = Arrays.copyOfRange(data, m.macOffset(), m.macOffset() + 16);
        byte[] expected = SimKeys.macSha1(
                keys.kAut(), SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, TYPE, data, m.macOffset()), sres);
        if (!MessageDigest.isEqual(received, expected)) {
            imsi = null;
            return Step.FAILED;
        }
        return Step.succeeded(keys.msk());
    }
}
