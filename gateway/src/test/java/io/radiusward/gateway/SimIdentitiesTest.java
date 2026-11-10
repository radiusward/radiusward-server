/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Pseudonyms and fast re-authentication identities of EAP-SIM/AKA/AKA′ (ADR 0061). */
class SimIdentitiesTest {

    static final String IMSI = "262011000000001";
    static final SimIdentities.Key K1 = new SimIdentities.Key('1', new byte[16]);
    static final SimIdentities.Key K2 =
            new SimIdentities.Key('2', "abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII));

    @Test
    void pseudonymsRoundTripPerMethodAndKey() {
        long[] now = {0};
        SimIdentities ids = new SimIdentities(List.of(K2, K1), Duration.ofHours(1), 16, 10, () -> now[0]);
        String p = ids.pseudonym(EapAka.TYPE_AKA, IMSI);
        assertThat(p).startsWith("22");
        assertThat(ids.pseudonym(EapAka.TYPE_AKA, IMSI))
                .as("a fresh one each time")
                .isNotEqualTo(p);
        assertThat(ids.imsiOf(EapAka.TYPE_AKA, p + "@wlan.example")).isEqualTo(IMSI);
        assertThat(ids.imsiOf(EapAka.TYPE_AKA_PRIME, p)).as("another method's").isNull();
        assertThat(ids.pseudonym(EapSim.TYPE, IMSI)).startsWith("32");
        assertThat(ids.pseudonym(EapAka.TYPE_AKA_PRIME, IMSI)).startsWith("72");

        SimIdentities retired = new SimIdentities(List.of(K1, K2), Duration.ZERO, 0, 1, () -> 0);
        assertThat(retired.imsiOf(EapAka.TYPE_AKA, p))
                .as("a listed older key still decrypts")
                .isEqualTo(IMSI);
        SimIdentities other = new SimIdentities(List.of(K1), Duration.ZERO, 0, 1, () -> 0);
        assertThat(other.imsiOf(EapAka.TYPE_AKA, p)).as("an unknown key").isNull();
        char[] forged = p.toCharArray();
        forged[forged.length - 3] = forged[forged.length - 3] == 'A' ? 'B' : 'A';
        assertThat(ids.imsiOf(EapAka.TYPE_AKA, new String(forged)))
                .as("a changed byte")
                .isNull();
        assertThat(ids.imsiOf(EapAka.TYPE_AKA, "22!!")).isNull();
        assertThat(ids.imsiOf(EapAka.TYPE_AKA, "2")).isNull();
        assertThat(SimIdentities.NONE.pseudonym(EapAka.TYPE_AKA, IMSI)).isNull();
        assertThat(SimIdentities.NONE.pseudonyms()).isFalse();
        assertThat(SimIdentities.NONE.reauthentication()).isFalse();
    }

    @Test
    void reauthenticationIdentitiesAreUsedOnceExpireAndStopAtTheMaximum() {
        long[] now = {1_000};
        SimIdentities ids = new SimIdentities(List.of(), Duration.ofSeconds(60), 2, 2, () -> now[0]);
        SimIdentities.Session s =
                new SimIdentities.Session(EapAka.TYPE_AKA, IMSI, new byte[20], new byte[16], new byte[16], null, 0, 0);
        String id = ids.keep(s);
        assertThat(id).startsWith("4");
        assertThat(ids.take(EapSim.TYPE, id)).as("another method's hint").isNull();
        SimIdentities.Session taken = ids.take(EapAka.TYPE_AKA, id + "@realm");
        assertThat(taken.imsi()).isEqualTo(IMSI);
        assertThat(taken.expires()).isEqualTo(61_000);
        assertThat(ids.take(EapAka.TYPE_AKA, id)).as("used once").isNull();

        String second = ids.keep(new SimIdentities.Session(
                EapAka.TYPE_AKA, IMSI, new byte[20], new byte[16], new byte[16], null, 1, taken.expires()));
        assertThat(ids.take(EapAka.TYPE_AKA, second).expires())
                .as("the first one's lifetime")
                .isEqualTo(61_000);
        assertThat(ids.keep(new SimIdentities.Session(
                        EapAka.TYPE_AKA, IMSI, new byte[20], new byte[16], new byte[16], null, 2, 61_000)))
                .as("the maximum reached: a full authentication next")
                .isNull();

        String old = ids.keep(s);
        now[0] = 61_001;
        assertThat(ids.take(EapAka.TYPE_AKA, old)).as("expired").isNull();
        ids.keep(s);
        ids.keep(s);
        assertThat(ids.keep(s)).as("full").isNull();
        now[0] = 200_000;
        assertThat(ids.keep(s)).as("expired ones make room").isNotNull();
        String dropped = ids.keep(s);
        ids.drop(dropped);
        ids.drop(null);
        assertThat(ids.take(EapAka.TYPE_AKA, dropped)).isNull();
    }

    @Test
    void encryptedAttributes() {
        byte[] kEncr = new byte[16];
        byte[] attrs = EapAka.withoutHeader(
                new SimMessage.Builder(0).uint16(SimMessage.AT_COUNTER, 7).build());
        byte[][] enc = SimIdentities.encrypt(kEncr, attrs);
        assertThat(enc[1]).hasSize(16);
        byte[] iv = new byte[18];
        System.arraycopy(enc[0], 0, iv, 2, 16);
        byte[] data = new byte[2 + enc[1].length];
        System.arraycopy(enc[1], 0, data, 2, enc[1].length);
        SimMessage m = SimIdentities.decrypt(kEncr, iv, data);
        assertThat(m.get(SimMessage.AT_COUNTER)).containsExactly(0, 7);
        assertThat(m.has(SimMessage.AT_PADDING)).isTrue();
        assertThat(SimIdentities.decrypt(kEncr, null, data)).isNull();
        assertThat(SimIdentities.decrypt(kEncr, iv, new byte[5])).isNull();
    }

    @Test
    void configuration() {
        SimConfig c = SimConfig.from(Config.of(Map.of(
                "auth.eap.sim.pseudonym.keys", "a:000102030405060708090a0b0c0d0e0f, b:0f0e0d0c0b0a09080706050403020100",
                "auth.eap.sim.reauth.lifetime", "10m",
                "auth.eap.aka-prime.network.name", "WLAN")));
        assertThat(c.identities().pseudonyms()).isTrue();
        assertThat(c.identities().pseudonym(EapAka.TYPE_AKA, IMSI)).startsWith("2a");
        assertThat(SimConfig.from(Config.of(Map.of("auth.eap.sim.reauth.lifetime", "0s")))
                        .identities()
                        .reauthentication())
                .isFalse();
        for (Map<String, String> bad : List.of(
                Map.of("auth.eap.sim.pseudonym.keys", "ab:000102030405060708090a0b0c0d0e0f"),
                Map.of("auth.eap.sim.pseudonym.keys", "a:0001"),
                Map.of(
                        "auth.eap.sim.pseudonym.keys",
                        "a:000102030405060708090a0b0c0d0e0f, a:000102030405060708090a0b0c0d0e0f"),
                Map.of("auth.eap.sim.reauth.max", "70000"))) {
            assertThatThrownBy(() -> SimConfig.from(Config.of(bad))).isInstanceOf(ConfigException.class);
        }
    }
}
