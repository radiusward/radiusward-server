/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code radsec.*} and {@code nas.<name>.radsec*} (ADR 0034); {@code radsec.dtls.*} and {@code nas.<name>.dtls*} (ADR 0038). */
class RadsecConfigTest {

    @TempDir
    static Path dir;

    static TestPki pki;

    @BeforeAll
    static void certificates() throws Exception {
        pki = new TestPki(dir, "radsec-config");
    }

    private Map<String, String> base() {
        return new HashMap<>(Map.ofEntries(
                Map.entry("radsec.enabled", "true"),
                Map.entry("radsec.certificate", pki.serverPem.toString()),
                Map.entry("radsec.key", pki.serverKey.toString()),
                Map.entry("radsec.ca", pki.caPem.toString()),
                Map.entry("nas.edge.address", "10.0.0.1"),
                Map.entry("nas.edge.radsec", "true"),
                Map.entry("nas.core.address", "10.0.0.2"),
                Map.entry("nas.core.radsec", "true"),
                Map.entry("nas.core.radsec.secret", "other"),
                Map.entry("nas.core.radsec.identity", "core.corp.test"),
                Map.entry("nas.plain.address", "10.0.0.3")));
    }

    @Test
    void offByDefault() {
        assertThat(RadsecConfig.from(Config.of(Map.of()), "0.0.0.0").enabled()).isFalse();
    }

    @Test
    void defaultsAndNasEntries() {
        RadsecConfig c = RadsecConfig.from(Config.of(base()), "0.0.0.0");
        assertThat(c.enabled()).isTrue();
        assertThat(c.port()).isEqualTo(2083);
        assertThat(c.versions()).containsExactly("TLSv1.2", "TLSv1.3");
        assertThat(c.connections()).isEqualTo(256);
        assertThat(c.handshakeTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(c.idleTimeout()).isZero();
        assertThat(c.clients()).containsOnlyKeys("edge", "core");
        assertThat(new String(c.clients().get("edge").secret(), StandardCharsets.UTF_8))
                .as("RFC 6614 §2.3")
                .isEqualTo("radsec");
        assertThat(c.clients().get("edge").identity()).isNull();
        assertThat(new String(c.clients().get("core").secret(), StandardCharsets.UTF_8))
                .isEqualTo("other");
        assertThat(c.clients().get("core").identity()).isEqualTo("core.corp.test");
        assertThat(c.credentials().current()).isNotNull();
    }

    @Test
    void mistakesAreConfigErrors() {
        for (String[] wrong : new String[][] {
            {"radsec.ca", "", "radsec.ca"},
            {"radsec.versions", "TLSv1.1", "radsec.versions"},
            {"radsec.connections", "0", "radsec.connections"},
            {"radsec.revocation", "crl", "radsec.crl"},
            {"radsec.key", pki.caPem.toString(), "radsec.key"}
        }) {
            Map<String, String> settings = base();
            settings.put(wrong[0], wrong[1]);
            assertThatThrownBy(() -> RadsecConfig.from(Config.of(settings), "0.0.0.0"))
                    .as(wrong[0])
                    .hasMessageContaining(wrong[2]);
        }
        Map<String, String> none = base();
        none.put("nas.edge.radsec", "false");
        none.put("nas.core.radsec", "false");
        assertThatThrownBy(() -> RadsecConfig.from(Config.of(none), "0.0.0.0"))
                .hasMessageContaining("nas.<name>.radsec");
    }

    @Test
    void dtlsAloneOrBesideTcp() {
        Map<String, String> settings = base();
        settings.put("radsec.enabled", "false");
        settings.put("radsec.dtls.enabled", "true");
        settings.put("nas.edge.dtls", "true");
        settings.put("nas.core.dtls", "true");
        settings.put("nas.core.dtls.secret", "dtls-other");
        settings.put("nas.core.dtls.identity", "core.corp.test");
        RadsecConfig c = RadsecConfig.from(Config.of(settings), "0.0.0.0");
        assertThat(c.enabled()).isTrue();
        assertThat(c.tcp()).isFalse();
        assertThat(c.clients()).as("no TCP clients without the TCP listener").isEmpty();
        RadsecConfig.Dtls dtls = c.dtls();
        assertThat(dtls.enabled()).isTrue();
        assertThat(dtls.port()).isEqualTo(2083);
        assertThat(dtls.associations()).isEqualTo(256);
        assertThat(dtls.idleTimeout()).isEqualTo(Duration.ofMinutes(15));
        assertThat(dtls.retransmit()).isEqualTo(Duration.ofSeconds(1));
        assertThat(new String(dtls.clients().get("edge").secret(), StandardCharsets.UTF_8))
                .as("RFC 7360 §2.1")
                .isEqualTo("radius/dtls");
        assertThat(dtls.clients().get("core").identity()).isEqualTo("core.corp.test");
        assertThat(new String(dtls.clients().get("core").secret(), StandardCharsets.UTF_8))
                .isEqualTo("dtls-other");
        assertThat(c.credentials().currentDtls().getProtocol()).isEqualTo("DTLS");
        assertThat(c.credentials().currentDtls())
                .as("built once per certificate set")
                .isSameAs(c.credentials().currentDtls());

        settings.put("radsec.enabled", "true");
        RadsecConfig both = RadsecConfig.from(Config.of(settings), "0.0.0.0");
        assertThat(both.tcp()).isTrue();
        assertThat(both.clients()).containsOnlyKeys("edge", "core");
        assertThat(both.dtls().clients()).containsOnlyKeys("edge", "core");
    }

    @Test
    void dtlsMistakesAreConfigErrors() {
        for (String[] wrong : new String[][] {
            {"radsec.dtls.associations", "0", "radsec.dtls.associations"},
            {"radsec.dtls.retransmit", "0s", "radsec.dtls.retransmit"},
            {"nas.edge.dtls", "false", "nas.<name>.dtls"}
        }) {
            Map<String, String> settings = base();
            settings.put("radsec.dtls.enabled", "true");
            settings.put("nas.edge.dtls", "true");
            settings.put(wrong[0], wrong[1]);
            assertThatThrownBy(() -> RadsecConfig.from(Config.of(settings), "0.0.0.0"))
                    .as(wrong[0])
                    .hasMessageContaining(wrong[2]);
        }
    }

    @Test
    void aNasEntryMayBeIdentifiedByItsDtlsCertificateAlone() {
        NasRegistry registry = NasRegistry.from(
                Config.of(Map.of("nas.roaming.dtls", "true", "nas.roaming.dtls.identity", "ap-7.corp.test")));
        assertThat(registry.clients())
                .singleElement()
                .satisfies(n -> assertThat(n.certificateOnly()).isTrue());
        assertThatThrownBy(() -> NasRegistry.from(Config.of(Map.of("nas.roaming.dtls", "true"))))
                .hasMessageContaining("dtls.identity");
    }

    @Test
    void plainTcpNeedsNoCertificates() {
        RadsecConfig c = RadsecConfig.from(
                Config.of(Map.of(
                        "radius.tcp.enabled", "true",
                        "nas.edge.address", "10.0.0.1",
                        "nas.edge.secret", "s",
                        "nas.edge.tcp", "true")),
                "0.0.0.0");
        assertThat(c.enabled()).isTrue();
        assertThat(c.tcp()).as("no RadSec listener").isFalse();
        assertThat(c.credentials()).isNull();
        assertThat(c.plain().enabled()).isTrue();
        assertThat(c.plain().authPort()).isEqualTo(1812);
        assertThat(c.plain().accountingPort()).isEqualTo(1813);
        assertThat(c.plain().clients()).containsExactly("edge");
        assertThatThrownBy(() -> RadsecConfig.from(
                        Config.of(Map.of("radius.tcp.enabled", "true", "nas.edge.address", "10.0.0.1")), "0.0.0.0"))
                .hasMessageContaining("nas.<name>.tcp");
        Map<String, String> both = base();
        both.put("radius.tcp.enabled", "true");
        both.put("nas.plain.tcp", "true");
        RadsecConfig withTls = RadsecConfig.from(Config.of(both), "0.0.0.0");
        assertThat(withTls.tcp()).isTrue();
        assertThat(withTls.plain().clients()).containsExactly("plain");
    }
}
