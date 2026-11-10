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
 * ADR 0061. The identity names the subscriber: {@code 0<IMSI>@realm} (AKA) or {@code 6<IMSI>@realm} (AKA′); another
 * identity gets an AKA-Identity request for the permanent one. The challenge carries RAND and AUTN with the next SQN
 * from the cluster (one sequence per subscriber for all gateways); a USIM out of step answers with AUTS, from which
 * the SQN is resynchronised once. RES and AT_MAC must match; the MSK becomes the MPPE keys. The IMSI is the user
 * authorized afterwards, like a tunnel's inner user.
 */
final class EapAka implements EapMethod {

    static final int TYPE_AKA = 23;
    static final int TYPE_AKA_PRIME = 50;

    static final int CHALLENGE = 1;
    static final int AUTHENTICATION_REJECT = 2;
    static final int SYNCHRONIZATION_FAILURE = 4;
    static final int IDENTITY = 5;
    static final int NOTIFICATION = 12;
    static final int CLIENT_ERROR = 14;
    static final int KDF_AKA_PRIME = 1;
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        IDENTITY,
        CHALLENGE,
        DONE
    }

    private final boolean prime;
    private final byte[] networkName;
    private State state;
    private byte[] identity; // as last received: the input of the key derivation
    private String imsi;
    private SimSubscriber subscriber;
    private byte[] rand;
    private byte[] xres;
    private SimKeys.Keys keys;
    private boolean resynchronised;
    private boolean identityAsked;

    /**
     * @param prime EAP-AKA′ instead of EAP-AKA
     * @param networkName AKA′'s network name ({@code auth.eap.aka-prime.network.name}), bound into its keys
     * @param identity the EAP-Response/Identity
     */
    EapAka(boolean prime, byte[] networkName, String identity) {
        this.prime = prime;
        this.networkName = networkName.clone();
        this.identity = identity == null ? new byte[0] : identity.getBytes(StandardCharsets.UTF_8);
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
        String permanent = permanentImsi(new String(identity, StandardCharsets.UTF_8), prime);
        if (permanent == null) {
            return askIdentity();
        }
        return challenge(identifier, credentials, permanent, 0);
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        SimMessage m = SimMessage.parse(data);
        if (m == null) {
            return Step.FAILED;
        }
        return switch (m.subtype()) {
            case IDENTITY -> onIdentity(identifier, m, credentials);
            case CHALLENGE -> state == State.CHALLENGE ? onChallenge(identifier, data, m) : Step.FAILED;
            case SYNCHRONIZATION_FAILURE -> onSynchronizationFailure(identifier, m, credentials);
            default -> Step.FAILED; // Authentication-Reject, Client-Error, anything else
        };
    }

    /** The IMSI of a permanent identity for this method ({@code 0…} AKA, {@code 6…} AKA′), else {@code null}. */
    static String permanentImsi(String identity, boolean prime) {
        if (identity.length() < 2 || identity.charAt(0) != (prime ? '6' : '0')) {
            return null;
        }
        int at = identity.indexOf('@');
        String imsi = identity.substring(1, at < 0 ? identity.length() : at);
        return imsi.matches("[0-9]{6,15}") ? imsi : null;
    }

    private Step askIdentity() {
        if (identityAsked) {
            return Step.FAILED; // asked once already: the peer has no usable identity
        }
        identityAsked = true;
        state = State.IDENTITY;
        return Step.next(new SimMessage.Builder(IDENTITY)
                .add(SimMessage.AT_PERMANENT_ID_REQ, new byte[2])
                .build());
    }

    private Step onIdentity(int identifier, SimMessage m, Credentials credentials) {
        byte[] value = SimMessage.lengthPrefixed(m.get(SimMessage.AT_IDENTITY));
        if (state != State.IDENTITY || value == null) {
            return Step.FAILED;
        }
        identity = value;
        String permanent = permanentImsi(new String(value, StandardCharsets.UTF_8), prime);
        return permanent == null ? Step.FAILED : challenge(identifier + 1, credentials, permanent, 0);
    }

    /** Looks the subscriber up, takes the next SQN from the cluster and sends RAND and AUTN. */
    private Step challenge(int identifier, Credentials credentials, String permanent, long floor) {
        if (subscriber == null) {
            EapMethod.Subscriber found = credentials.inner().subscriber(permanent);
            if (found.code() == AccessHandler.DROP) {
                return Step.STORE_UNAVAILABLE;
            }
            if (found.code() != AccessHandler.ACCEPT) {
                return Step.FAILED;
            }
            try {
                subscriber = SimSubscriber.of(found.checks());
            } catch (IllegalArgumentException e) {
                return Step.FAILED; // logged by the handler's subscriber look-up
            }
            if (!subscriber.milenage()) {
                return Step.FAILED; // no Ki and OPc: AKA needs MILENAGE
            }
            imsi = permanent;
        }
        long sqn = credentials.inner().nextSqn(imsi, Math.max(floor, subscriber.sqn()));
        if (sqn == SessionLimits.SQN_UNAVAILABLE) {
            return Step.STORE_UNAVAILABLE;
        }
        if (sqn < 0) {
            return Step.FAILED; // the cluster keeps no sequence numbers yet (state version 8 not active)
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
        xres = q.res();
        SimMessage.Builder b = new SimMessage.Builder(CHALLENGE)
                .reserved(SimMessage.AT_RAND, rand)
                .reserved(SimMessage.AT_AUTN, autn);
        if (prime) {
            byte[][] ckIk = SimKeys.akaPrimeCkIk(q.ck(), q.ik(), networkName, Arrays.copyOfRange(autn, 0, 6));
            keys = SimKeys.akaPrimeKeys(ckIk[0], ckIk[1], identity);
            b.lengthPrefixed(SimMessage.AT_KDF_INPUT, networkName).uint16(SimMessage.AT_KDF, KDF_AKA_PRIME);
        } else {
            keys = SimKeys.fullKeys(SimKeys.akaMasterKey(identity, q.ik(), q.ck()));
        }
        b.mac();
        byte[] data = b.build();
        byte[] mac = mac(SimMessage.packet(EapPacket.CODE_REQUEST, identifier, type(), data, b.macOffset()));
        System.arraycopy(mac, 0, data, b.macOffset(), 16);
        state = State.CHALLENGE;
        return Step.next(data);
    }

    private Step onChallenge(int identifier, byte[] data, SimMessage m) {
        state = State.DONE;
        if (m.macOffset() < 0 || !macValid(identifier, data, m)) {
            imsi = null;
            return Step.FAILED;
        }
        byte[] res = m.get(SimMessage.AT_RES);
        if (res == null || res.length < 2) {
            imsi = null;
            return Step.FAILED;
        }
        int bits = ((res[0] & 0xFF) << 8) | (res[1] & 0xFF);
        if (bits != xres.length * 8
                || res.length < 2 + xres.length
                || !MessageDigest.isEqual(Arrays.copyOfRange(res, 2, 2 + xres.length), xres)) {
            imsi = null;
            return Step.FAILED;
        }
        return Step.succeeded(keys.msk());
    }

    private Step onSynchronizationFailure(int identifier, SimMessage m, Credentials credentials) {
        byte[] auts = m.get(SimMessage.AT_AUTS);
        if (state != State.CHALLENGE || resynchronised || auts == null || auts.length != 14) {
            return Step.FAILED;
        }
        byte[] sqnMs = new Milenage(subscriber.ki(), subscriber.opc()).resync(rand, auts);
        if (sqnMs == null) {
            return Step.FAILED; // MAC-S does not verify: not from this USIM
        }
        resynchronised = true;
        long floor = 0;
        for (byte b : sqnMs) {
            floor = floor << 8 | (b & 0xFF);
        }
        return challenge(identifier + 1, credentials, imsi, floor);
    }

    private boolean macValid(int identifier, byte[] data, SimMessage m) {
        byte[] received = Arrays.copyOfRange(data, m.macOffset(), m.macOffset() + 16);
        byte[] expected = mac(SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, type(), data, m.macOffset()));
        return MessageDigest.isEqual(received, expected);
    }

    private byte[] mac(byte[] packet) {
        return prime ? SimKeys.macSha256(keys.kAut(), packet, null) : SimKeys.macSha1(keys.kAut(), packet, null);
    }
}
