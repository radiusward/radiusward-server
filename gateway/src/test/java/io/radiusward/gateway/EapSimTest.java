/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.gateway.EapAkaTest.IMSI;
import static io.radiusward.gateway.EapAkaTest.KI;
import static io.radiusward.gateway.EapAkaTest.OPC;
import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** EAP-SIM (ADR 0061) against a SIM written here from GSM-MILENAGE; interop with wpa_supplicant: {@code AkaEapolIT}. */
class EapSimTest {

    static final byte[] NONCE = new byte[16];

    /** A SIM: answers Start with its nonce (and identity), the Challenge with its SRES under AT_MAC. */
    static final class Sim {
        final String identity;
        byte[] ki = KI;

        Sim(String identity) {
            this.identity = identity;
        }

        byte[] start(SimMessage request, boolean giveIdentity, int version) {
            SimMessage.Builder b = new SimMessage.Builder(EapSim.START)
                    .reserved(SimMessage.AT_NONCE_MT, NONCE)
                    .uint16(SimMessage.AT_SELECTED_VERSION, version);
            if (giveIdentity) {
                b.lengthPrefixed(SimMessage.AT_IDENTITY, identity.getBytes(StandardCharsets.UTF_8));
            }
            return b.build();
        }

        byte[] challenge(int identifier, byte[] request) {
            SimMessage m = SimMessage.parse(request);
            byte[] rands = m.get(SimMessage.AT_RAND);
            Milenage milenage = new Milenage(ki, OPC);
            byte[][] kc = new byte[3][];
            byte[] sres = new byte[12];
            for (int i = 0; i < 3; i++) {
                Milenage.Triplet t = milenage.gsm(Arrays.copyOfRange(rands, 2 + 16 * i, 18 + 16 * i));
                kc[i] = t.kc();
                System.arraycopy(t.sres(), 0, sres, 4 * i, 4);
            }
            byte[] kAut = SimKeys.fullKeys(SimKeys.simMasterKey(
                            identity.getBytes(StandardCharsets.UTF_8), kc, NONCE, new byte[] {0, 1}, 1))
                    .kAut();
            SimMessage.Builder b = new SimMessage.Builder(EapSim.CHALLENGE).mac();
            byte[] data = b.build();
            byte[] mac = SimKeys.macSha1(
                    kAut,
                    SimMessage.packet(EapPacket.CODE_RESPONSE, identifier, EapSim.TYPE, data, b.macOffset()),
                    sres);
            System.arraycopy(mac, 0, data, b.macOffset(), 16);
            return data;
        }
    }

    static EapMethod.Credentials credentials(EapAkaTest.Side side) {
        return new EapMethod.Credentials(List.of(), false, side);
    }

    @Test
    void permanentAndAskedIdentitiesSucceed() {
        for (String outer : new String[] {"1" + IMSI + "@realm", "anonymous@realm"}) {
            boolean asked = outer.startsWith("anonymous");
            EapSim sim = new EapSim(outer);
            EapAkaTest.Side side = new EapAkaTest.Side();
            EapMethod.Step start = sim.start(1, credentials(side));
            SimMessage request = SimMessage.parse(start.request());
            assertThat(request.has(SimMessage.AT_VERSION_LIST)).isTrue();
            assertThat(request.has(SimMessage.AT_PERMANENT_ID_REQ)).isEqualTo(asked);
            Sim peer = new Sim(asked ? "1" + IMSI : outer);
            EapMethod.Step challenge = sim.process(1, peer.start(request, asked, 1), credentials(side));
            EapMethod.Step done = sim.process(2, peer.challenge(2, challenge.request()), credentials(side));
            assertThat(done.success()).as(outer).isTrue();
            assertThat(done.msk()).hasSize(64);
            assertThat(sim.innerIdentity()).isEqualTo(IMSI);
        }
    }

    @Test
    void wrongKeysVersionsAndMissingPartsFail() {
        String identity = "1" + IMSI;
        EapAkaTest.Side side = new EapAkaTest.Side();
        EapSim sim = new EapSim(identity);
        SimMessage request = SimMessage.parse(sim.start(1, credentials(side)).request());
        Sim other = new Sim(identity);
        other.ki = new byte[16];
        EapMethod.Step challenge = sim.process(1, other.start(request, false, 1), credentials(side));
        assertThat(sim.process(2, other.challenge(2, challenge.request()), credentials(side))
                        .success())
                .as("SRES of another key")
                .isFalse();

        EapSim version = new EapSim(identity);
        SimMessage r = SimMessage.parse(version.start(1, credentials(side)).request());
        assertThat(version.process(1, new Sim(identity).start(r, false, 2), credentials(side))
                        .success())
                .isFalse();

        EapSim noIdentity = new EapSim("anonymous");
        SimMessage asked =
                SimMessage.parse(noIdentity.start(1, credentials(side)).request());
        assertThat(noIdentity
                        .process(1, new Sim(identity).start(asked, false, 1), credentials(side))
                        .success())
                .as("asked for the identity, none given")
                .isFalse();

        EapSim noNonce = new EapSim(identity);
        noNonce.start(1, credentials(side));
        assertThat(noNonce.process(
                                1,
                                new SimMessage.Builder(EapSim.START)
                                        .uint16(SimMessage.AT_SELECTED_VERSION, 1)
                                        .build(),
                                credentials(side))
                        .success())
                .isFalse();
        EapSim outOfTurn = new EapSim(identity);
        outOfTurn.start(1, credentials(side));
        assertThat(outOfTurn
                        .process(1, new SimMessage.Builder(EapSim.CHALLENGE).build(), credentials(side))
                        .success())
                .isFalse();
        assertThat(outOfTurn.process(1, new byte[] {1}, credentials(side)).success())
                .isFalse();
    }

    @Test
    void storesThatCannotAnswerAndUnusableTriplets() {
        String identity = "1" + IMSI;
        EapAkaTest.Side down = new EapAkaTest.Side();
        down.subscriberCode = AccessHandler.DROP;
        EapSim sim = new EapSim(identity);
        SimMessage r = SimMessage.parse(sim.start(1, credentials(down)).request());
        assertThat(sim.process(1, new Sim(identity).start(r, false, 1), credentials(down))
                        .unavailable())
                .isTrue();

        // stored triplets with a repeated RAND are refused (RFC 4186 §6.2)
        String rand = "00000000000000000000000000000001";
        EapMethod.InnerAuth repeated = new EapAkaTest.Side() {
            @Override
            public EapMethod.Subscriber subscriber(String imsi) {
                List<AttributeItem> items = new java.util.ArrayList<>();
                for (int i = 1; i <= 3; i++) {
                    items.add(new AttributeItem("EAP-Sim-Rand" + i, ":=", rand));
                    items.add(new AttributeItem("EAP-Sim-SRES" + i, ":=", "11111111"));
                    items.add(new AttributeItem(
                            "EAP-Sim-KC" + i, ":=", HexFormat.of().formatHex(new byte[8])));
                }
                return new EapMethod.Subscriber(AccessHandler.ACCEPT, items);
            }
        };
        EapSim stored = new EapSim(identity);
        EapMethod.Credentials c = new EapMethod.Credentials(List.of(), false, repeated);
        SimMessage s = SimMessage.parse(stored.start(1, c).request());
        assertThat(stored.process(1, new Sim(identity).start(s, false, 1), c).success())
                .isFalse();
        assertThat(EapSim.permanentImsi("0" + IMSI)).as("an AKA identity").isNull();
        assertThat(EapSim.permanentImsi("1" + IMSI + "@realm")).isEqualTo(IMSI);
    }
}
