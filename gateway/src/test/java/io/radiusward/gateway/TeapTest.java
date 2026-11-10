/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.io.ByteArrayOutputStream;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** TEAP's TLV parsing and configuration (ADR 0041); conversations: {@code EapolTestIT}, {@code ExternalEapComparisonIT}. */
class TeapTest {

    @TempDir
    Path dir;

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    @Test
    void tlvsAreParsed() {
        byte[] eap = new EapPacket(EapPacket.CODE_RESPONSE, 7, EapPacket.TYPE_IDENTITY, new byte[] {'a'}).encode();
        Teap.Tlvs t = Teap.Tlvs.parse(concat(
                Teap.tlv(Teap.MANDATORY | Teap.TLV_RESULT, new byte[] {0, 1}),
                Teap.tlv(Teap.MANDATORY | Teap.TLV_INTERMEDIATE_RESULT, new byte[] {0, 2}),
                Teap.tlv(Teap.MANDATORY | Teap.TLV_EAP_PAYLOAD, concat(eap, new byte[] {0, 2, 0, 2, 0, 1})),
                Teap.tlv(Teap.TLV_NAK, new byte[6]),
                Teap.tlv(77, new byte[3]))); // an unknown optional TLV is skipped
        assertThat(t.result).isEqualTo(Teap.SUCCESS);
        assertThat(t.intermediate).isEqualTo(Teap.FAILURE);
        assertThat(t.eapPayload).as("the EAP packet without the TLVs after it").isEqualTo(eap);
        assertThat(t.nak).isTrue();
        assertThat(Teap.Tlvs.parse(Teap.tlv(Teap.MANDATORY | 77, new byte[1])))
                .as("an unknown mandatory TLV")
                .isNull();
        assertThat(Teap.Tlvs.parse(new byte[] {0, 3, 0, 9, 0})).as("truncated").isNull();
        assertThat(Teap.Tlvs.parse(new byte[] {0, 3}))
                .as("no room for a header")
                .isNull();
        assertThat(Teap.Tlvs.parse(Teap.tlv(Teap.TLV_RESULT, new byte[] {1})).result)
                .as("a malformed status is a failure")
                .isEqualTo(Teap.FAILURE);
    }

    @Test
    void configuration() throws Exception {
        TestPki pki = new TestPki(dir, "teap");
        Map<String, String> base = new HashMap<>(Map.of(
                "auth.eap.methods", "teap",
                "auth.eap.tls.certificate", pki.serverPem.toString(),
                "auth.eap.tls.key", pki.serverKey.toString(),
                "auth.eap.tls.ca", pki.caPem.toString()));
        EapConfig defaults = EapConfig.from(Config.of(base));
        assertThat(defaults.teapInner()).containsExactly(InnerEap.MS_CHAP_V2, InnerEap.GTC, InnerEap.MD5);
        assertThat(defaults.teapIdentity()).isEmpty();
        assertThat(new String(defaults.teapAuthorityId())).isEqualTo("radiusward");
        assertThat(defaults.outerOptional(Teap.TYPE)).isTrue();
        assertThat(defaults.create(Teap.TYPE, "anonymous")).isInstanceOf(Teap.class);

        Map<String, String> set = new HashMap<>(base);
        set.put("auth.eap.teap.inner", "tls, basic");
        set.put("auth.eap.teap.identity", "machine, user");
        set.put("auth.eap.teap.authority.id", "aaa.corp.example");
        EapConfig custom = EapConfig.from(Config.of(set));
        assertThat(custom.teapInner()).containsExactly(InnerEap.TLS, Teap.BASIC);
        assertThat(custom.teapIdentity()).containsExactly(Teap.IDENTITY_MACHINE, Teap.IDENTITY_USER);

        for (String[] wrong : new String[][] {
            {"auth.eap.teap.inner", "pap", "auth.eap.teap.inner"},
            {"auth.eap.teap.identity", "device", "auth.eap.teap.identity"},
            {"auth.eap.teap.identity", "user, user", "auth.eap.teap.identity"},
            {"auth.eap.teap.authority.id", "x".repeat(256), "auth.eap.teap.authority.id"}
        }) {
            Map<String, String> bad = new HashMap<>(base);
            bad.put(wrong[0], wrong[1]);
            assertThatThrownBy(() -> EapConfig.from(Config.of(bad))).hasMessageContaining(wrong[2]);
        }
        Map<String, String> noCa = new HashMap<>(base);
        noCa.remove("auth.eap.tls.ca");
        noCa.put("auth.eap.teap.inner", "tls");
        assertThatThrownBy(() -> EapConfig.from(Config.of(noCa))).hasMessageContaining("tls needs auth.eap.tls.ca");
        assertThat(List.of(EapConfig.type("teap"))).containsExactly(Teap.TYPE);
    }
}
