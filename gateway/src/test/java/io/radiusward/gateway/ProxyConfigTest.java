/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** {@code proxy.*}, {@code realm.*}, {@code pool.*}, {@code home.*} and realm matching (ADR 0037). */
class ProxyConfigTest {

    static Map<String, String> base() {
        return new HashMap<>(Map.of(
                "proxy.enabled", "true",
                "home.a.address", "127.0.0.1:1812",
                "home.a.secret", "s",
                "home.b.address", "127.0.0.2",
                "home.b.secret", "s",
                "pool.p.servers", "a, b",
                "realm.partner.name", "Partner.Example",
                "realm.partner.pool", "p",
                "realm.rest.name", "*",
                "realm.rest.pool", "p"));
    }

    static String realm(ProxyConfig c, String user) {
        byte[] b = user.getBytes(StandardCharsets.UTF_8);
        ProxyConfig.Realm r = c.realmOf(new UnsafeBuffer(b), 0, b.length);
        return r == null ? null : r.name();
    }

    @Test
    void offByDefault() {
        assertThat(ProxyConfig.from(Config.of(Map.of())).enabled()).isFalse();
    }

    @Test
    void realmsMatchSuffixAndPrefixCaseFolded() {
        ProxyConfig c = ProxyConfig.from(Config.of(base()));
        assertThat(realm(c, "alice@partner.example")).isEqualTo("partner.example");
        assertThat(realm(c, "alice@PARTNER.EXAMPLE")).isEqualTo("partner.example");
        assertThat(realm(c, "PARTNER.EXAMPLE\\alice")).isEqualTo("partner.example");
        assertThat(realm(c, "alice@other.org")).as("any other realm").isEqualTo("*");
        assertThat(realm(c, "alice")).as("no realm: local").isNull();
        assertThat(realm(c, "alice@")).as("an empty realm: local").isNull();
        assertThat(c.homes().get("a").port()).isEqualTo(1812);
        assertThat(c.homes().get("b").port()).isEqualTo(1812);
        assertThat(c.pools().get("p").loadBalance()).isFalse();
        assertThat(c.requireMessageAuthenticator()).isTrue();

        Map<String, String> local = base();
        local.remove("realm.rest.name");
        local.remove("realm.rest.pool");
        assertThat(realm(ProxyConfig.from(Config.of(local)), "alice@other.org"))
                .as("without *: other realms are local")
                .isNull();
    }

    @Test
    void mistakes() {
        for (String[] wrong : new String[][] {
            {"realm.partner.pool", "nope", "realm.partner.pool"},
            {"pool.p.servers", "a, c", "pool.p.servers"},
            {"pool.p.type", "random", "pool.p.type"},
            {"home.a.transport", "sctp", "home.a.transport"},
            {"home.a.secret", "", "home.a.secret"},
            {"home.c.transport", "tls", "home.c."}
        }) {
            Map<String, String> settings = base();
            settings.put(wrong[0], wrong[1]);
            if (wrong[0].startsWith("home.c")) {
                settings.put("home.c.address", "127.0.0.1");
            }
            assertThatThrownBy(() -> ProxyConfig.from(Config.of(settings)))
                    .as(wrong[0])
                    .hasMessageContaining(wrong[2]);
        }
        assertThatThrownBy(() -> ProxyConfig.from(Config.of(Map.of("proxy.enabled", "true"))))
                .hasMessageContaining("realm");
    }

    @Test
    void coaRelayFromHomeServers() {
        ProxyConfig none = ProxyConfig.from(Config.of(base()));
        assertThat(none.coaRelay()).as("no home server sends CoA").isFalse();
        assertThat(none.coaPort()).isEqualTo(3799);
        Map<String, String> settings = base();
        settings.put("home.a.coa", "true");
        settings.put("proxy.coa.port", "13799");
        ProxyConfig relay = ProxyConfig.from(Config.of(settings));
        assertThat(relay.coaRelay()).isTrue();
        assertThat(relay.coaPort()).isEqualTo(13799);
        assertThat(relay.homes().get("a").relaysCoa()).isTrue();
        assertThat(relay.homes().get("b").relaysCoa()).isFalse();
        assertThat(ProxyConfig.DISABLED.coaRelay()).isFalse();

        Map<String, String> tls = base();
        tls.put("home.a.transport", "tls");
        tls.put("home.a.tls.ca", "/dev/null");
        tls.put("home.a.coa", "true");
        assertThatThrownBy(() -> ProxyConfig.from(Config.of(tls))).hasMessageContaining("over UDP only");
    }
}
