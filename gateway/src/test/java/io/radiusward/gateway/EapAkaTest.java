/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.gateway.MilenageTest.hex;
import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * EAP-AKA and EAP-AKA′ (ADR 0061) against a USIM written here from MILENAGE: success, the identity request, a USIM out
 * of step, forged and malformed responses, and a store or cluster that cannot answer. Interop with wpa_supplicant:
 * {@code AkaEapolIT}.
 */
class EapAkaTest {

    static final byte[] KI = hex("465b5ce8b199b49faa5f0a2ee238a6bc");
    static final byte[] OPC = hex("cd63cb71954a9f4e48a5994e37a02baf");
    static final String IMSI = "262011000000001";
    static final byte[] WLAN = "WLAN".getBytes(StandardCharsets.US_ASCII);

    /** The gateway side: one subscriber, sequence numbers from a counter, or answers set by the test. */
    static class Side implements EapMethod.InnerAuth {
        int subscriberCode = AccessHandler.ACCEPT;
        long sqn = 0;
        long forced = 0; // non-zero: nextSqn answers this
        long lastFloor;

        @Override
        public EapMethod.Inner msChapV2(String user, EapMethod.MsChapV2 exchange) {
            return new EapMethod.Inner(AccessHandler.REJECT, null);
        }

        @Override
        public EapMethod.Inner password(String user, byte[] password) {
            return new EapMethod.Inner(AccessHandler.REJECT, null);
        }

        @Override
        public EapMethod.Subscriber subscriber(String imsi) {
            if (!imsi.equals(IMSI) || subscriberCode != AccessHandler.ACCEPT) {
                return new EapMethod.Subscriber(imsi.equals(IMSI) ? subscriberCode : AccessHandler.REJECT, List.of());
            }
            return new EapMethod.Subscriber(
                    AccessHandler.ACCEPT,
                    List.of(
                            new AttributeItem("SIM-Ki", ":=", "0x465b5ce8b199b49faa5f0a2ee238a6bc"),
                            new AttributeItem("SIM-OPc", ":=", "cd63cb71954a9f4e48a5994e37a02baf")));
        }

        @Override
        public long nextSqn(String imsi, long floor) {
            lastFloor = floor;
            if (forced != 0) {
                return forced;
            }
            sqn = (Math.max(sqn, floor) / 32 + 1) * 32;
            return sqn;
        }
    }

    /** A USIM: checks AUTN, answers RES with AT_MAC, or AUTS when the SQN is not newer than its own. */
    static final class Usim {
        final boolean prime;
        final String identity;
        long sqnMs;
        byte[] ki = KI;

        Usim(boolean prime, String identity, long sqnMs) {
            this.prime = prime;
            this.identity = identity;
            this.sqnMs = sqnMs;
        }

        byte[] answer(int identifier, byte[] request) {
            SimMessage m = SimMessage.parse(request);
            byte[] rand = Arrays.copyOfRange(m.get(SimMessage.AT_RAND), 2, 18);
            byte[] autn = Arrays.copyOfRange(m.get(SimMessage.AT_AUTN), 2, 18);
            Milenage milenage = new Milenage(ki, OPC);
            Milenage.Quintet q = milenage.f2345(rand);
            byte[] sqn = new byte[6];
            for (int i = 0; i < 6; i++) {
                sqn[i] = (byte) (autn[i] ^ q.ak()[i]);
            }
            byte[] mac = milenage.f1(rand, sqn, Arrays.copyOfRange(autn, 6, 8));
            if (!Arrays.equals(Arrays.copyOfRange(mac, 0, 8), Arrays.copyOfRange(autn, 8, 16))) {
                return new SimMessage.Builder(EapAka.AUTHENTICATION_REJECT).build();
            }
            long received = 0;
            for (byte b : sqn) {
                received = received << 8 | (b & 0xFF);
            }
            if (received <= sqnMs) {
                byte[] ms = new byte[6];
                for (int i = 0; i < 6; i++) {
                    ms[i] = (byte) (sqnMs >>> (40 - 8 * i));
                }
                byte[] auts = new byte[14];
                for (int i = 0; i < 6; i++) {
                    auts[i] = (byte) (ms[i] ^ q.akStar()[i]);
                }
                System.arraycopy(milenage.f1(rand, ms, new byte[2]), 8, auts, 6, 8);
                return new SimMessage.Builder(EapAka.SYNCHRONIZATION_FAILURE)
                        .add(SimMessage.AT_AUTS, auts)
                        .build();
            }
            sqnMs = received;
            byte[] id = identity.getBytes(StandardCharsets.UTF_8);
            byte[] kAut;
            if (prime) {
                byte[][] ckIk = SimKeys.akaPrimeCkIk(q.ck(), q.ik(), WLAN, Arrays.copyOfRange(autn, 0, 6));
                kAut = SimKeys.akaPrimeKeys(ckIk[0], ckIk[1], id).kAut();
            } else {
                kAut = SimKeys.fullKeys(SimKeys.akaMasterKey(id, q.ik(), q.ck()))
                        .kAut();
            }
            byte[] res = new byte[2 + q.res().length];
            res[1] = (byte) (q.res().length * 8);
            System.arraycopy(q.res(), 0, res, 2, q.res().length);
            SimMessage.Builder b = new SimMessage.Builder(EapAka.CHALLENGE)
                    .add(SimMessage.AT_RES, res)
                    .mac();
            byte[] data = b.build();
            byte[] packet = SimMessage.packet(
                    EapPacket.CODE_RESPONSE,
                    identifier,
                    prime ? EapAka.TYPE_AKA_PRIME : EapAka.TYPE_AKA,
                    data,
                    b.macOffset());
            byte[] mac2 = prime ? SimKeys.macSha256(kAut, packet, null) : SimKeys.macSha1(kAut, packet, null);
            System.arraycopy(mac2, 0, data, b.macOffset(), 16);
            return data;
        }
    }

    static EapMethod.Credentials credentials(Side side) {
        return new EapMethod.Credentials(List.of(), false, side);
    }

    @Test
    void akaAndAkaPrimeSucceedWithMatchingKeys() {
        for (boolean prime : new boolean[] {false, true}) {
            String identity = (prime ? "6" : "0") + IMSI + "@wlan.mnc001.mcc262.3gppnetwork.org";
            Side side = new Side();
            EapAka aka = new EapAka(prime, WLAN, identity);
            EapMethod.Step challenge = aka.start(5, credentials(side));
            assertThat(challenge.done()).isFalse();
            assertThat(aka.innerIdentity()).as("not before success").isNull();
            Usim usim = new Usim(prime, identity, 0);
            EapMethod.Step done = aka.process(5, usim.answer(5, challenge.request()), credentials(side));
            assertThat(done.success()).as(prime ? "AKA'" : "AKA").isTrue();
            assertThat(done.msk()).hasSize(64);
            assertThat(aka.innerIdentity()).isEqualTo(IMSI);
            assertThat(aka.type()).isEqualTo(prime ? 50 : 23);
        }
    }

    @Test
    void anOtherIdentityIsAskedForAndAUsimAheadIsResynchronised() {
        Side side = new Side();
        EapAka aka = new EapAka(false, WLAN, "anonymous@realm");
        EapMethod.Step ask = aka.start(1, credentials(side));
        SimMessage request = SimMessage.parse(ask.request());
        assertThat(request.subtype()).isEqualTo(EapAka.IDENTITY);
        assertThat(request.has(SimMessage.AT_PERMANENT_ID_REQ)).isTrue();
        String identity = "0" + IMSI;
        byte[] answer = new SimMessage.Builder(EapAka.IDENTITY)
                .lengthPrefixed(SimMessage.AT_IDENTITY, identity.getBytes(StandardCharsets.UTF_8))
                .build();
        EapMethod.Step challenge = aka.process(1, answer, credentials(side));
        Usim usim = new Usim(false, identity, 4096);
        EapMethod.Step again = aka.process(2, usim.answer(2, challenge.request()), credentials(side));
        assertThat(side.lastFloor).as("the USIM's SQN as the floor").isEqualTo(4096);
        assertThat(again.done()).isFalse();
        EapMethod.Step done = aka.process(3, usim.answer(3, again.request()), credentials(side));
        assertThat(done.success()).isTrue();

        EapAka twice = new EapAka(false, WLAN, "0" + IMSI);
        Side stuck = new Side();
        stuck.forced = 32; // the cluster keeps answering an old SQN
        Usim ahead = new Usim(false, "0" + IMSI, 4096);
        EapMethod.Step c1 = twice.start(1, credentials(stuck));
        EapMethod.Step c2 = twice.process(1, ahead.answer(1, c1.request()), credentials(stuck));
        assertThat(twice.process(2, ahead.answer(2, c2.request()), credentials(stuck))
                        .success())
                .as("one resynchronisation per authentication")
                .isFalse();
    }

    @Test
    void forgedOrMalformedResponsesFail() {
        String identity = "0" + IMSI;
        Side side = new Side();
        EapAka aka = new EapAka(false, WLAN, identity);
        EapMethod.Step challenge = aka.start(1, credentials(side));
        byte[] answer = new Usim(false, identity, 0).answer(1, challenge.request());
        answer[answer.length - 1] ^= 1; // the MAC
        assertThat(aka.process(1, answer, credentials(side)).success()).isFalse();

        EapAka wrongKey = new EapAka(false, WLAN, identity);
        Usim other = new Usim(false, identity, 0);
        other.ki = new byte[16];
        EapMethod.Step c = wrongKey.start(1, credentials(side));
        assertThat(wrongKey.process(1, other.answer(1, c.request()), credentials(side))
                        .success())
                .as("the USIM rejects the AUTN")
                .isFalse();

        EapAka garbage = new EapAka(false, WLAN, identity);
        garbage.start(1, credentials(side));
        assertThat(garbage.process(1, new byte[] {1, 0}, credentials(side)).success())
                .isFalse();
        EapAka unknownAttribute = new EapAka(false, WLAN, identity);
        unknownAttribute.start(1, credentials(side));
        assertThat(unknownAttribute
                        .process(1, new byte[] {1, 0, 0, 99, 1, 0, 0}, credentials(side))
                        .success())
                .isFalse();
        EapAka identityLate = new EapAka(false, WLAN, identity);
        identityLate.start(1, credentials(side));
        assertThat(identityLate
                        .process(
                                1,
                                new SimMessage.Builder(EapAka.IDENTITY)
                                        .lengthPrefixed(SimMessage.AT_IDENTITY, new byte[] {'0'})
                                        .build(),
                                credentials(side))
                        .success())
                .as("an identity answer without having asked")
                .isFalse();
    }

    @Test
    void storesAndTheClusterThatCannotAnswer() {
        String identity = "0" + IMSI;
        Side down = new Side();
        down.subscriberCode = AccessHandler.DROP;
        assertThat(new EapAka(false, WLAN, identity).start(1, credentials(down)).unavailable())
                .isTrue();
        Side unknown = new Side();
        assertThat(new EapAka(false, WLAN, "0262019999999999")
                        .start(1, credentials(unknown))
                        .success())
                .isFalse();
        Side noCluster = new Side();
        noCluster.forced = SessionLimits.SQN_UNAVAILABLE;
        assertThat(new EapAka(false, WLAN, identity)
                        .start(1, credentials(noCluster))
                        .unavailable())
                .isTrue();
        Side oldCluster = new Side();
        oldCluster.forced = SessionLimits.SQN_UNSUPPORTED;
        EapMethod.Step s = new EapAka(false, WLAN, identity).start(1, credentials(oldCluster));
        assertThat(s.done() && !s.success() && !s.unavailable()).isTrue();
    }

    @Test
    void permanentIdentities() {
        assertThat(EapAka.permanentImsi("0262011000000001@realm", false)).isEqualTo("262011000000001");
        assertThat(EapAka.permanentImsi("6262011000000001", true)).isEqualTo("262011000000001");
        assertThat(EapAka.permanentImsi("6262011000000001", false))
                .as("AKA' hint for AKA")
                .isNull();
        assertThat(EapAka.permanentImsi("2pseudonym@realm", false)).isNull();
        assertThat(EapAka.permanentImsi("0", false)).isNull();
        assertThat(EapAka.permanentImsi("0abc", false)).isNull();
    }
}
