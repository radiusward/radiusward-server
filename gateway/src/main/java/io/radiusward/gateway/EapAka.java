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
 * EAP-AKA (RFC 4187) and EAP-AKA′ (RFC 9048) with vectors computed here from the subscriber's Ki and OPc (MILENAGE),
 * ADR 0061. The identity names the subscriber: permanent ({@code 0<IMSI>@realm}, AKA′ {@code 6…}), a pseudonym this
 * server issued, or a fast re-authentication identity it keeps; anything else gets an AKA-Identity request. The
 * challenge carries RAND and AUTN with the next SQN from the cluster (one sequence per subscriber for all gateways);
 * a USIM out of step answers with AUTS, from which the SQN is resynchronised once. RES and AT_MAC must match; the
 * MSK becomes the MPPE keys. With {@link SimIdentities}, the challenge also hands out the next pseudonym and
 * re-authentication identity in AT_ENCR_DATA. The IMSI is the user authorized afterwards, like a tunnel's inner user.
 */
final class EapAka implements EapMethod {

    static final int TYPE_AKA = 23;
    static final int TYPE_AKA_PRIME = 50;

    static final int CHALLENGE = 1;
    static final int AUTHENTICATION_REJECT = 2;
    static final int SYNCHRONIZATION_FAILURE = 4;
    static final int IDENTITY = 5;
    static final int NOTIFICATION = 12;
    static final int REAUTHENTICATION = 13;
    static final int CLIENT_ERROR = 14;
    static final int KDF_AKA_PRIME = 1;
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        IDENTITY,
        CHALLENGE,
        REAUTHENTICATION,
        DONE
    }

    private final boolean prime;
    private final byte[] networkName;
    private final SimIdentities identities;
    private State state;
    private byte[] peerIdentity; // as last received: the input of the key derivation
    private String imsi;
    private SimSubscriber subscriber;
    private byte[] rand;
    private byte[] xres;
    private SimKeys.Keys keys;
    private byte[] mk; // AKA: the master key, kept for re-authentication
    private boolean resynchronised;
    private boolean identityAsked;
    private String nextReauthId;
    private SimIdentities.Session reauth;
    private int counter;
    private byte[] nonceS;

    /**
     * @param prime EAP-AKA′ instead of EAP-AKA
     * @param networkName AKA′'s network name ({@code auth.eap.aka-prime.network.name}), bound into its keys
     * @param identity the EAP-Response/Identity
     * @param identities pseudonyms and re-authentication ({@link SimIdentities#NONE}: neither)
     */
    EapAka(boolean prime, byte[] networkName, String identity, SimIdentities identities) {
        this.prime = prime;
        this.networkName = networkName.clone();
        this.peerIdentity = identity == null ? new byte[0] : identity.getBytes(StandardCharsets.UTF_8);
        this.identities = identities;
    }

    EapAka(boolean prime, byte[] networkName, String identity) {
        this(prime, networkName, identity, SimIdentities.NONE);
    }

    @Override
    public int type() {
        return prime ? TYPE_AKA_PRIME : TYPE_AKA;
    }

    @Override
    public String innerIdentity() {
        return state == State.DONE ? imsi : null;
    }

    @Override
    public Step start(int identifier, Credentials credentials) {
        Step step = byIdentity(identifier, credentials);
        return step != null ? step : askIdentity();
    }

    /** Permanent, re-authentication or pseudonym identity; {@code null} if it is none of them. */
    private Step byIdentity(int identifier, Credentials credentials) {
        String id = new String(peerIdentity, StandardCharsets.UTF_8);
        String permanent = permanentImsi(id, prime);
        if (permanent != null) {
            return challenge(identifier, credentials, permanent, 0);
        }
        SimIdentities.Session session = identities.take(type(), id);
        if (session != null) {
            return reauthenticate(identifier, session);
        }
        String pseudonymous = identities.imsiOf(type(), id);
        return pseudonymous != null ? challenge(identifier, credentials, pseudonymous, 0) : null;
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        SimMessage m = SimMessage.parse(data);
        if (m == null) {
            return fail();
        }
        return switch (m.subtype()) {
            case IDENTITY -> onIdentity(identifier, m, credentials);
            case CHALLENGE -> state == State.CHALLENGE ? onChallenge(identifier, data, m) : fail();
            case SYNCHRONIZATION_FAILURE -> onSynchronizationFailure(identifier, m, credentials);
            case REAUTHENTICATION -> state == State.REAUTHENTICATION ? onReauthentication(identifier, data, m) : fail();
            default -> fail(); // Authentication-Reject, Client-Error, anything else
        };
    }

    /** The IMSI of a permanent identity for this method ({@code 0…} AKA, {@code 6…} AKA′), else {@code null}. */
    static String permanentImsi(String identity, boolean prime) {
        if (identity.length() < 2 || identity.charAt(0) != (prime ? '6' : '0')) {
            return null;
        }
        String imsi = SimIdentities.withoutRealm(identity).substring(1);
        return imsi.matches("[0-9]{6,15}") ? imsi : null;
    }

    private Step askIdentity() {
        if (identityAsked) {
            return fail(); // asked once already: the peer has no usable identity
        }
        identityAsked = true;
        state = State.IDENTITY;
        int request = identities.pseudonyms() || identities.reauthentication()
                ? SimMessage.AT_ANY_ID_REQ
                : SimMessage.AT_PERMANENT_ID_REQ;
        return Step.next(
                new SimMessage.Builder(IDENTITY).add(request, new byte[2]).build());
    }

    private Step onIdentity(int identifier, SimMessage m, Credentials credentials) {
        byte[] value = SimMessage.lengthPrefixed(m.get(SimMessage.AT_IDENTITY));
        if (state != State.IDENTITY || value == null) {
            return fail();
        }
        peerIdentity = value;
        Step step = byIdentity(identifier + 1, credentials);
        return step != null ? step : fail();
    }

    /** Looks the subscriber up, takes the next SQN from the cluster and sends RAND and AUTN. */
    private Step challenge(int identifier, Credentials credentials, String permanent, long floor) {
        if (subscriber == null) {
            EapMethod.Subscriber found = credentials.inner().subscriber(permanent);
            if (found.code() == AccessHandler.DROP) {
                return Step.STORE_UNAVAILABLE;
            }
            if (found.code() != AccessHandler.ACCEPT) {
                return fail();
            }
            try {
                subscriber = SimSubscriber.of(found.checks());
            } catch (IllegalArgumentException e) {
                return fail(); // logged by the handler's subscriber look-up
            }
            if (!subscriber.usesMilenage()) {
                return fail(); // no Ki and OPc: AKA needs MILENAGE (fail() erases what there is)
            }
            imsi = permanent;
        }
        long sqn = credentials.inner().nextSqn(imsi, Math.max(floor, subscriber.sqn()));
        if (sqn == SessionLimits.SQN_UNAVAILABLE) {
            return Step.STORE_UNAVAILABLE;
        }
        if (sqn < 0) {
            return fail(); // the cluster keeps no sequence numbers yet (state version 8 not active)
        }
        byte[] sqnBytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            sqnBytes[i] = (byte) (sqn >>> (40 - 8 * i));
        }
        byte[] amf = subscriber.amf() != null ? subscriber.amf() : prime ? new byte[] {(byte) 0x80, 0} : new byte[2];
        Milenage milenage = new Milenage(subscriber.ki(), subscriber.opc());
        rand = new byte[16];
        RANDOM.nextBytes(rand);
        Milenage.Quintet q = milenage.f2345(rand);
        byte[] autn = milenage.autn(rand, sqnBytes, amf);
        milenage.erase();
        if (resynchronised) {
            forgetSubscriber(); // no second resynchronisation: Ki and OPc are not needed again
        }
        xres = q.res();
        SimMessage.Builder b = new SimMessage.Builder(CHALLENGE)
                .reserved(SimMessage.AT_RAND, rand)
                .reserved(SimMessage.AT_AUTN, autn);
        if (prime) {
            byte[][] ckIk = SimKeys.akaPrimeCkIk(q.ck(), q.ik(), networkName, Arrays.copyOfRange(autn, 0, 6));
            keys = SimKeys.akaPrimeKeys(ckIk[0], ckIk[1], peerIdentity);
            b.lengthPrefixed(SimMessage.AT_KDF_INPUT, networkName).uint16(SimMessage.AT_KDF, KDF_AKA_PRIME);
        } else {
            mk = SimKeys.akaMasterKey(peerIdentity, q.ik(), q.ck());
            keys = SimKeys.fullKeys(mk);
        }
        identities.drop(nextReauthId); // a resynchronised challenge replaces the first one's
        nextReauthId = identities.keep(
                new SimIdentities.Session(type(), imsi, mk, keys.kAut(), keys.kEncr(), keys.kRe(), 0, 0));
        nextIdentities(b, keys.kEncr(), identities.pseudonym(type(), imsi), nextReauthId);
        state = State.CHALLENGE;
        return Step.next(signed(b, identifier, keys.kAut()));
    }

    private Step onChallenge(int identifier, byte[] data, SimMessage m) {
        if (!macValid(identifier, data, m, keys.kAut(), null)) {
            return fail();
        }
        byte[] res = m.get(SimMessage.AT_RES);
        if (res == null || res.length < 2) {
            return fail();
        }
        int bits = ((res[0] & 0xFF) << 8) | (res[1] & 0xFF);
        if (bits != xres.length * 8
                || res.length < 2 + xres.length
                || !MessageDigest.isEqual(Arrays.copyOfRange(res, 2, 2 + xres.length), xres)) {
            return fail();
        }
        state = State.DONE;
        forgetSubscriber();
        return Step.succeeded(keys.msk());
    }

    private Step onSynchronizationFailure(int identifier, SimMessage m, Credentials credentials) {
        byte[] auts = m.get(SimMessage.AT_AUTS);
        if (state != State.CHALLENGE || resynchronised || auts == null || auts.length != 14) {
            return fail();
        }
        Milenage milenage = new Milenage(subscriber.ki(), subscriber.opc());
        byte[] sqnMs = milenage.resync(rand, auts);
        milenage.erase();
        if (sqnMs == null) {
            return fail(); // MAC-S does not verify: not from this USIM
        }
        resynchronised = true;
        long floor = 0;
        for (byte b : sqnMs) {
            floor = floor << 8 | (b & 0xFF);
        }
        return challenge(identifier + 1, credentials, imsi, floor);
    }

    /**
     * Fast re-authentication (RFC 4187 §5, RFC 9048 §3.3): the counter and NONCE_S in AT_ENCR_DATA with the next
     * re-authentication identity, under the kept K_encr and K_aut. No vector, no cluster.
     */
    private Step reauthenticate(int identifier, SimIdentities.Session session) {
        reauth = session;
        imsi = session.imsi();
        counter = session.counter() + 1;
        nonceS = new byte[16];
        RANDOM.nextBytes(nonceS);
        nextReauthId = identities.keep(new SimIdentities.Session(
                type(),
                imsi,
                session.mk(),
                session.kAut(),
                session.kEncr(),
                session.kRe(),
                counter,
                session.expires()));
        SimMessage.Builder inner = new SimMessage.Builder(0)
                .uint16(SimMessage.AT_COUNTER, counter)
                .reserved(SimMessage.AT_NONCE_S, nonceS);
        if (nextReauthId != null) {
            inner.lengthPrefixed(SimMessage.AT_NEXT_REAUTH_ID, nextReauthId.getBytes(StandardCharsets.UTF_8));
        }
        byte[][] encrypted = SimIdentities.encrypt(session.kEncr(), withoutHeader(inner.build()));
        SimMessage.Builder b = new SimMessage.Builder(REAUTHENTICATION)
                .reserved(SimMessage.AT_IV, encrypted[0])
                .reserved(SimMessage.AT_ENCR_DATA, encrypted[1]);
        state = State.REAUTHENTICATION;
        return Step.next(signed(b, identifier, session.kAut()));
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
            return fail(); // the peer refused the counter: it authenticates in full next time
        }
        SimKeys.Keys k = prime
                ? SimKeys.akaPrimeReauthKeys(reauth.kRe(), peerIdentity, counter, nonceS)
                : SimKeys.reauthKeys(peerIdentity, counter, nonceS, reauth.mk());
        state = State.DONE;
        return Step.succeeded(k.msk());
    }

    /** AT_IV and AT_ENCR_DATA with the next pseudonym and re-authentication identity, if there are any. */
    static void nextIdentities(SimMessage.Builder b, byte[] kEncr, String pseudonym, String reauthId) {
        if (pseudonym == null && reauthId == null) {
            return;
        }
        SimMessage.Builder inner = new SimMessage.Builder(0);
        if (pseudonym != null) {
            inner.lengthPrefixed(SimMessage.AT_NEXT_PSEUDONYM, pseudonym.getBytes(StandardCharsets.UTF_8));
        }
        if (reauthId != null) {
            inner.lengthPrefixed(SimMessage.AT_NEXT_REAUTH_ID, reauthId.getBytes(StandardCharsets.UTF_8));
        }
        byte[][] encrypted = SimIdentities.encrypt(kEncr, withoutHeader(inner.build()));
        b.reserved(SimMessage.AT_IV, encrypted[0]).reserved(SimMessage.AT_ENCR_DATA, encrypted[1]);
    }

    static byte[] withoutHeader(byte[] typeData) {
        return Arrays.copyOfRange(typeData, 3, typeData.length);
    }

    /** Adds AT_MAC over the request and returns the type data. */
    private byte[] signed(SimMessage.Builder b, int identifier, byte[] kAut) {
        b.mac();
        byte[] data = b.build();
        byte[] mac =
                mac(kAut, SimMessage.packet(EapPacket.CODE_REQUEST, identifier, type(), data, b.macOffset()), null);
        System.arraycopy(mac, 0, data, b.macOffset(), 16);
        return data;
    }

    private boolean macValid(int identifier, byte[] data, SimMessage m, byte[] kAut, byte[] extra) {
        if (m.macOffset() < 0) {
            return false;
        }
        byte[] received = Arrays.copyOfRange(data, m.macOffset(), m.macOffset() + 16);
        byte[] expected =
                mac(kAut, SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, type(), data, m.macOffset()), extra);
        return MessageDigest.isEqual(received, expected);
    }

    private byte[] mac(byte[] kAut, byte[] packet, byte[] extra) {
        return prime ? SimKeys.macSha256(kAut, packet, extra) : SimKeys.macSha1(kAut, packet, extra);
    }

    /** Zeroes Ki and OPc, kept until the challenge is answered in case the USIM asks for resynchronisation. */
    private void forgetSubscriber() {
        if (subscriber != null) {
            subscriber.erase();
            subscriber = null;
        }
    }

    /** Fails the authentication: no identity authorized, the handed-out re-authentication identity forgotten. */
    private Step fail() {
        state = State.DONE;
        imsi = null;
        forgetSubscriber();
        identities.drop(nextReauthId);
        nextReauthId = null;
        return Step.FAILED;
    }
}
