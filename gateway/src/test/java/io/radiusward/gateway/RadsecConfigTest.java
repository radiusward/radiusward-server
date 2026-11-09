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

/** {@code radsec.*} and {@code nas.<name>.radsec*} (ADR 0034). */
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
}
