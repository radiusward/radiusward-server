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
 * subscriber's Ki and OPc, or the three triplets stored for it (weaker: the same RANDs every time). A fast
 * re-authentication identity this server keeps gets the Re-authentication request at once; otherwise the Start round
 * offers the version and, unless the identity is permanent ({@code 1<IMSI>@realm}) or a pseudonym it issued, asks
 * for one; the peer answers with its NONCE_MT. The challenge's AT_MAC covers the NONCE_MT, the response's the three
 * SRES; with {@link SimIdentities} the challenge also hands out the next pseudonym and re-authentication identity.
 * The IMSI is authorized afterwards, like a tunnel's inner user.
 */
final class EapSim implements EapMethod {

    static final int TYPE = 18;
    static final int START = 10;
    static final int CHALLENGE = 11;
    static final int REAUTHENTICATION = 13;
    static final int CLIENT_ERROR = 14;
    static final int VERSION = 1;
    private static final byte[] VERSION_LIST = {0, VERSION};
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        START,
        CHALLENGE,
        REAUTHENTICATION,
        DONE
    }

    private final SimIdentities identities;
    private State state;
    private byte[] identity;
    private String imsi;
    private boolean identityAsked;
    private byte[] sres;
    private SimKeys.Keys keys;
    private String nextReauthId;
    private SimIdentities.Session reauth;
    private int counter;
    private byte[] nonceS;

    /**
     * @param identity the EAP-Response/Identity
     * @param identities pseudonyms and re-authentication ({@link SimIdentities#NONE}: neither)
     */
    EapSim(String identity, SimIdentities identities) {
        this.identity = identity == null ? new byte[0] : identity.getBytes(StandardCharsets.UTF_8);
        this.identities = identities;
    }

    EapSim(String identity) {
        this(identity, SimIdentities.NONE);
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    public String innerIdentity() {
        return state == State.DONE ? imsi : null;
    }

    /** Re-authentication for a kept identity; otherwise SIM-Start, asking for an identity unless it has a usable one. */
    @Override
    public Step start(int identifier, Credentials credentials) {
        String id = new String(identity, StandardCharsets.UTF_8);
        SimIdentities.Session session = identities.take(TYPE, id);
        if (session != null) {
            return reauthenticate(identifier, session);
        }
        state = State.START;
        SimMessage.Builder b = new SimMessage.Builder(START).lengthPrefixed(SimMessage.AT_VERSION_LIST, VERSION_LIST);
        if (imsiOf(id) == null) {
            identityAsked = true;
            b.add(
                    identities.pseudonyms() ? SimMessage.AT_FULLAUTH_ID_REQ : SimMessage.AT_PERMANENT_ID_REQ,
                    new byte[2]);
        }
        return Step.next(b.build());
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        SimMessage m = SimMessage.parse(data);
        if (m == null) {
            return fail();
        }
        if (m.subtype() == START && state == State.START) {
            return onStart(identifier, m, credentials);
        }
        if (m.subtype() == CHALLENGE && state == State.CHALLENGE) {
            return onChallenge(identifier, data, m);
        }
        if (m.subtype() == REAUTHENTICATION && state == State.REAUTHENTICATION) {
            return onReauthentication(identifier, data, m);
        }
        return fail(); // Client-Error, a message out of turn
    }

    /** The IMSI of a permanent EAP-SIM identity ({@code 1…}), else {@code null}. */
    static String permanentImsi(String identity) {
        if (identity.length() < 2 || identity.charAt(0) != '1') {
            return null;
        }
        String imsi = SimIdentities.withoutRealm(identity).substring(1);
        return imsi.matches("[0-9]{6,15}") ? imsi : null;
    }

    private String imsiOf(String id) {
        String permanent = permanentImsi(id);
        return permanent != null ? permanent : identities.imsiOf(TYPE, id);
    }

    private Step onStart(int identifier, SimMessage m, Credentials credentials) {
        byte[] nonce = m.get(SimMessage.AT_NONCE_MT);
        byte[] selected = m.get(SimMessage.AT_SELECTED_VERSION);
        if (nonce == null || nonce.length != 18 || selected == null || selected.length < 2) {
            return fail();
        }
        if (((selected[0] & 0xFF) << 8 | (selected[1] & 0xFF)) != VERSION) {
            return fail();
        }
        byte[] given = SimMessage.lengthPrefixed(m.get(SimMessage.AT_IDENTITY));
        if (given != null) {
            identity = given;
        } else if (identityAsked) {
            return fail(); // asked for an identity and got none
        }
        String permanent = imsiOf(new String(identity, StandardCharsets.UTF_8));
        if (permanent == null) {
            return fail();
        }
        EapMethod.Subscriber found = credentials.inner().subscriber(permanent);
        if (found.code() == AccessHandler.DROP) {
            return Step.STORE_UNAVAILABLE;
        }
        if (found.code() != AccessHandler.ACCEPT) {
            return fail();
        }
        SimSubscriber subscriber;
        try {
            subscriber = SimSubscriber.of(found.checks());
        } catch (IllegalArgumentException e) {
            return fail();
        }
        Milenage.Triplet[] triplets = triplets(subscriber);
        subscriber.erase();
        if (triplets == null) {
            return fail();
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
        byte[] mk = SimKeys.simMasterKey(identity, kc, nonceMt, VERSION_LIST, VERSION);
        keys = SimKeys.fullKeys(mk);
        SimMessage.Builder b = new SimMessage.Builder(CHALLENGE).reserved(SimMessage.AT_RAND, rands);
        nextReauthId =
                identities.keep(new SimIdentities.Session(TYPE, imsi, mk, keys.kAut(), keys.kEncr(), null, 0, 0));
        EapAka.nextIdentities(b, keys.kEncr(), identities.pseudonym(TYPE, imsi), nextReauthId);
        state = State.CHALLENGE;
        return Step.next(signed(b, identifier + 1, keys.kAut(), nonceMt));
    }

    /** Three triplets with distinct RANDs: from GSM-MILENAGE, else the stored ones; {@code null} if neither. */
    private static Milenage.Triplet[] triplets(SimSubscriber subscriber) {
        Milenage.Triplet[] t = new Milenage.Triplet[3];
        if (subscriber.usesMilenage()) {
            Milenage milenage = new Milenage(subscriber.ki(), subscriber.opc());
            for (int i = 0; i < 3; i++) {
                byte[] rand = new byte[16];
                RANDOM.nextBytes(rand);
                t[i] = milenage.gsm(rand);
            }
            milenage.erase();
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
        if (!macValid(identifier, data, m, keys.kAut(), sres)) {
            return fail();
        }
        state = State.DONE;
        return Step.succeeded(keys.msk());
    }

    /** Fast re-authentication (RFC 4186 §5): the counter and NONCE_S under the kept keys. */
    private Step reauthenticate(int identifier, SimIdentities.Session session) {
        reauth = session;
        imsi = session.imsi();
        counter = session.counter() + 1;
        nonceS = new byte[16];
        RANDOM.nextBytes(nonceS);
        nextReauthId = identities.keep(new SimIdentities.Session(
                TYPE, imsi, session.mk(), session.kAut(), session.kEncr(), null, counter, session.expires()));
        SimMessage.Builder inner = new SimMessage.Builder(0)
                .uint16(SimMessage.AT_COUNTER, counter)
                .reserved(SimMessage.AT_NONCE_S, nonceS);
        if (nextReauthId != null) {
            inner.lengthPrefixed(SimMessage.AT_NEXT_REAUTH_ID, nextReauthId.getBytes(StandardCharsets.UTF_8));
        }
        byte[][] encrypted = SimIdentities.encrypt(session.kEncr(), EapAka.withoutHeader(inner.build()));
        SimMessage.Builder b = new SimMessage.Builder(REAUTHENTICATION)
                .reserved(SimMessage.AT_IV, encrypted[0])
                .reserved(SimMessage.AT_ENCR_DATA, encrypted[1]);
        state = State.REAUTHENTICATION;
        return Step.next(signed(b, identifier, session.kAut(), null));
    }

    private Step onReauthentication(int identifier, byte[] data, SimMessage m) {
        if (!macValid(identifier, data, m, reauth.kAut(), nonceS)) {
            return fail();
        }
        SimMessage inner =
                SimIdentities.decrypt(reauth.kEncr(), m.get(SimMessage.AT_IV), m.get(SimMessage.AT_ENCR_DATA));
        byte[] count = inner == null ? null : inner.get(SimMessage.AT_COUNTER);
        if (count == null
                || count.length < 2
                || ((count[0] & 0xFF) << 8 | (count[1] & 0xFF)) != counter
                || inner.has(SimMessage.AT_COUNTER_TOO_SMALL)) {
            return fail();
        }
        state = State.DONE;
        return Step.succeeded(
                SimKeys.reauthKeys(identity, counter, nonceS, reauth.mk()).msk());
    }

    private static byte[] signed(SimMessage.Builder b, int identifier, byte[] kAut, byte[] extra) {
        b.mac();
        byte[] data = b.build();
        byte[] mac = SimKeys.macSha1(
                kAut, SimMessage.packet(EapPacket.CODE_REQUEST, identifier, TYPE, data, b.macOffset()), extra);
        System.arraycopy(mac, 0, data, b.macOffset(), 16);
        return data;
    }

    private static boolean macValid(int identifier, byte[] data, SimMessage m, byte[] kAut, byte[] extra) {
        if (m.macOffset() < 0) {
            return false;
        }
        byte[] received = Arrays.copyOfRange(data, m.macOffset(), m.macOffset() + 16);
        byte[] expected = SimKeys.macSha1(
                kAut, SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, TYPE, data, m.macOffset()), extra);
        return MessageDigest.isEqual(received, expected);
    }

    private Step fail() {
        state = State.DONE;
        imsi = null;
        identities.drop(nextReauthId);
        nextReauthId = null;
        return Step.FAILED;
    }
}
