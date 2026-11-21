/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.eap.EapPacket;
import io.radiusward.eap.Milenage;
import io.radiusward.eap.SimKeys;
import io.radiusward.eap.SimMessage;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * EAP-SIM (RFC 4186), EAP-AKA (RFC 4187) and EAP-AKA′ (RFC 9048) with the login's {@link SimCard}: the permanent
 * identity, the card's MILENAGE answers and the keys of RFC 4186 §7, RFC 4187 §7 and RFC 9048 §3.3. The network is
 * checked as a device checks it (AUTN, then the server's AT_MAC); a network that fails is answered with
 * Authentication-Reject or Client-Error, an old sequence number with Synchronization-Failure.
 */
final class SimPeer {

    private static final int AKA_CHALLENGE = 1;
    private static final int AKA_AUTHENTICATION_REJECT = 2;
    private static final int AKA_SYNCHRONIZATION_FAILURE = 4;
    private static final int AKA_IDENTITY = 5;
    private static final int SIM_START = 10;
    private static final int SIM_CHALLENGE = 11;
    private static final int CLIENT_ERROR = 14;
    private static final int SIM_VERSION = 1;

    private final EapLogin login;
    private final int type;
    private final byte[] identity;
    private byte[] nonceMt;
    private byte[] versionList;

    SimPeer(EapLogin login, int type) {
        this.login = login;
        this.type = type;
        this.identity = login.identity().getBytes(StandardCharsets.UTF_8);
    }

    boolean serverProved;
    byte[] msk;

    byte[] answer(int identifier, byte[] request) {
        SimMessage m = SimMessage.parse(request);
        if (m == null) {
            return clientError();
        }
        int subtype = m.subtype();
        if (login.method == EapLogin.Method.SIM) {
            return switch (subtype) {
                case SIM_START -> start(m);
                case SIM_CHALLENGE -> simChallenge(identifier, request, m);
                default -> clientError();
            };
        }
        return switch (subtype) {
            case AKA_IDENTITY ->
                new SimMessage.Builder(AKA_IDENTITY)
                        .lengthPrefixed(SimMessage.AT_IDENTITY, identity)
                        .build();
            case AKA_CHALLENGE -> akaChallenge(identifier, request, m);
            default -> clientError();
        };
    }

    /** Version 1 selected, a fresh NONCE_MT, the permanent identity when the server asks for one. */
    private byte[] start(SimMessage m) {
        versionList = SimMessage.lengthPrefixed(m.get(SimMessage.AT_VERSION_LIST));
        if (versionList == null) {
            return clientError();
        }
        nonceMt = new byte[16];
        EapBytes.RANDOM.nextBytes(nonceMt);
        SimMessage.Builder b = new SimMessage.Builder(SIM_START)
                .reserved(SimMessage.AT_NONCE_MT, nonceMt)
                .uint16(SimMessage.AT_SELECTED_VERSION, SIM_VERSION);
        if (m.get(SimMessage.AT_PERMANENT_ID_REQ) != null
                || m.get(SimMessage.AT_FULLAUTH_ID_REQ) != null
                || m.get(SimMessage.AT_ANY_ID_REQ) != null) {
            b.lengthPrefixed(SimMessage.AT_IDENTITY, identity);
        }
        return b.build();
    }

    /** Three GSM triplets from the card; the server's MAC over NONCE_MT checked; our MAC over the SRESs. */
    private byte[] simChallenge(int identifier, byte[] request, SimMessage m) {
        byte[] rands = m.get(SimMessage.AT_RAND);
        if (nonceMt == null || rands == null || rands.length != 2 + 48) {
            return clientError();
        }
        Milenage milenage = login.card.milenage();
        byte[][] kc = new byte[3][];
        byte[] sres = new byte[12];
        for (int i = 0; i < 3; i++) {
            Milenage.Triplet t = milenage.gsm(Arrays.copyOfRange(rands, 2 + 16 * i, 18 + 16 * i));
            kc[i] = t.kc();
            System.arraycopy(t.sres(), 0, sres, 4 * i, 4);
        }
        milenage.erase();
        SimKeys.Keys keys = SimKeys.fullKeys(SimKeys.simMasterKey(identity, kc, nonceMt, versionList, SIM_VERSION));
        if (!serverMacValid(identifier, request, m, keys.kAut(), nonceMt)) {
            return clientError();
        }
        serverProved = true;
        msk = keys.msk();
        return signed(new SimMessage.Builder(SIM_CHALLENGE), identifier, keys.kAut(), sres);
    }

    /** AUTN checked by the card (MAC, then freshness), the server's MAC, then RES under our MAC. */
    private byte[] akaChallenge(int identifier, byte[] request, SimMessage m) {
        byte[] randAttribute = m.get(SimMessage.AT_RAND);
        byte[] autnAttribute = m.get(SimMessage.AT_AUTN);
        if (randAttribute == null
                || randAttribute.length != 18
                || autnAttribute == null
                || autnAttribute.length != 18) {
            return clientError();
        }
        byte[] rand = Arrays.copyOfRange(randAttribute, 2, 18);
        byte[] autn = Arrays.copyOfRange(autnAttribute, 2, 18);
        Milenage milenage = login.card.milenage();
        try {
            Milenage.Quintet q = milenage.f2345(rand);
            byte[] sqn = new byte[6];
            for (int i = 0; i < 6; i++) {
                sqn[i] = (byte) (autn[i] ^ q.ak()[i]);
            }
            byte[] mac = milenage.f1(rand, sqn, Arrays.copyOfRange(autn, 6, 8));
            if (!MessageDigest.isEqual(Arrays.copyOfRange(mac, 0, 8), Arrays.copyOfRange(autn, 8, 16))) {
                return new SimMessage.Builder(AKA_AUTHENTICATION_REJECT).build(); // not our network
            }
            long received = 0;
            for (byte b : sqn) {
                received = received << 8 | (b & 0xFF);
            }
            if (received <= login.card.sqn()) {
                return synchronizationFailure(milenage, rand, q);
            }
            SimKeys.Keys keys;
            if (login.method == EapLogin.Method.AKA_PRIME) {
                byte[] network = SimMessage.lengthPrefixed(m.get(SimMessage.AT_KDF_INPUT));
                if (network == null || network.length == 0) {
                    return clientError();
                }
                byte[][] ckIk = SimKeys.akaPrimeCkIk(q.ck(), q.ik(), network, Arrays.copyOfRange(autn, 0, 6));
                keys = SimKeys.akaPrimeKeys(ckIk[0], ckIk[1], identity);
            } else {
                keys = SimKeys.fullKeys(SimKeys.akaMasterKey(identity, q.ik(), q.ck()));
            }
            if (!serverMacValid(identifier, request, m, keys.kAut(), null)) {
                return clientError();
            }
            login.card.accepted(received);
            serverProved = true;
            msk = keys.msk();
            byte[] res = new byte[2 + q.res().length];
            res[1] = (byte) (q.res().length * 8);
            System.arraycopy(q.res(), 0, res, 2, q.res().length);
            return signed(
                    new SimMessage.Builder(AKA_CHALLENGE).add(SimMessage.AT_RES, res), identifier, keys.kAut(), null);
        } finally {
            milenage.erase();
        }
    }

    /** AUTS: the card's SQN concealed with AK* and signed with MAC-S (f1*), so the network can resume from it. */
    private byte[] synchronizationFailure(Milenage milenage, byte[] rand, Milenage.Quintet q) {
        long ms = login.card.sqn();
        byte[] sqnMs = new byte[6];
        for (int i = 0; i < 6; i++) {
            sqnMs[i] = (byte) (ms >>> (40 - 8 * i));
        }
        byte[] auts = new byte[14];
        for (int i = 0; i < 6; i++) {
            auts[i] = (byte) (sqnMs[i] ^ q.akStar()[i]);
        }
        System.arraycopy(milenage.f1(rand, sqnMs, new byte[2]), 8, auts, 6, 8);
        return new SimMessage.Builder(AKA_SYNCHRONIZATION_FAILURE)
                .add(SimMessage.AT_AUTS, auts)
                .build();
    }

    private boolean serverMacValid(int identifier, byte[] request, SimMessage m, byte[] kAut, byte[] extra) {
        int at = m.macOffset();
        if (at < 0) {
            return false;
        }
        byte[] packet = SimMessage.packet(EapPacket.CODE_REQUEST, identifier, type, request, at);
        return MessageDigest.isEqual(mac(kAut, packet, extra), Arrays.copyOfRange(request, at, at + 16));
    }

    private byte[] signed(SimMessage.Builder b, int identifier, byte[] kAut, byte[] extra) {
        byte[] data = b.mac().build();
        byte[] packet = SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, type, data, b.macOffset());
        System.arraycopy(mac(kAut, packet, extra), 0, data, b.macOffset(), 16);
        return data;
    }

    private byte[] mac(byte[] kAut, byte[] packet, byte[] extra) {
        return type == EapPacket.TYPE_AKA_PRIME
                ? SimKeys.macSha256(kAut, packet, extra)
                : SimKeys.macSha1(kAut, packet, extra);
    }

    /** Client-Error with code 0, "unable to process packet": the server ends the conversation. */
    private byte[] clientError() {
        return new SimMessage.Builder(CLIENT_ERROR)
                .uint16(SimMessage.AT_CLIENT_ERROR_CODE, 0)
                .build();
    }
}
