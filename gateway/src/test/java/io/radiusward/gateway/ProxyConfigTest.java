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

    @Test
    void tcpAndDtlsHomeServers() {
        Map<String, String> settings = base();
        settings.put("home.t.address", "127.0.0.1");
        settings.put("home.t.transport", "tcp");
        settings.put("home.t.secret", "s");
        settings.put("home.d.address", "127.0.0.1");
        settings.put("home.d.transport", "dtls");
        settings.put("home.d.tls.ca", "/ca.pem");
        ProxyConfig c = ProxyConfig.from(Config.of(settings));
        ProxyConfig.Home t = c.homes().get("t");
        assertThat(t.transport()).isEqualTo(ProxyConfig.Transport.TCP);
        assertThat(t.port()).isEqualTo(1812);
        assertThat(t.tls()).isFalse();
        ProxyConfig.Home d = c.homes().get("d");
        assertThat(d.transport()).isEqualTo(ProxyConfig.Transport.DTLS);
        assertThat(d.port()).isEqualTo(2083);
        assertThat(new String(d.secret(), StandardCharsets.UTF_8)).isEqualTo("radius/dtls");
        assertThat(c.homes().get("a").transport()).isEqualTo(ProxyConfig.Transport.UDP);

        Map<String, String> noSecret = base();
        noSecret.put("home.t.address", "127.0.0.1");
        noSecret.put("home.t.transport", "tcp");
        assertThatThrownBy(() -> ProxyConfig.from(Config.of(noSecret))).hasMessageContaining("home.t.secret");
        Map<String, String> noCa = base();
        noCa.put("home.d.address", "127.0.0.1");
        noCa.put("home.d.transport", "dtls");
        assertThatThrownBy(() -> ProxyConfig.from(Config.of(noCa))).hasMessageContaining("home.d.tls.ca");
        Map<String, String> coa = new HashMap<>(settings);
        coa.put("home.t.coa", "true");
        assertThatThrownBy(() -> ProxyConfig.from(Config.of(coa))).hasMessageContaining("over UDP only");
        Map<String, String> unknown = base();
        unknown.put("home.a.transport", "sctp");
        assertThatThrownBy(() -> ProxyConfig.from(Config.of(unknown))).hasMessageContaining("udp, tls, tcp or dtls");
    }

    @Test
    void rewritesAreCheckedAgainstTheDictionary() {
        io.radiusward.radius.dictionary.Dictionary dictionary = StoreAccessHandlerTest.DICTIONARY;
        Map<String, String> settings = base();
        settings.put("realm.partner.pre-proxy.remove", "Calling-Station-Id, NAS-Port");
        settings.put("realm.partner.pre-proxy.add", "Operator-Name = \"1op.example\", Cisco-AVPair += \"a=b\"");
        settings.put("realm.partner.post-proxy.remove", "Class");
        ProxyConfig c = ProxyConfig.from(Config.of(settings));
        ProxyRewrite r = realmNamed(c, "partner.example").rewrite();
        assertThat(r.any()).isTrue();
        r.compile(dictionary, "realm partner: ");
        assertThat(r.dropsFromRequest(31)).isTrue();
        assertThat(r.dropsFromRequest(5)).isTrue();
        assertThat(r.dropsFromRequest(1)).isFalse();
        assertThat(r.dropsFromAnswer(25)).isTrue();
        assertThat(r.added()[0]).as("Operator-Name first").isEqualTo((byte) 126);
        assertThat(r.added()).hasSizeGreaterThan(2 + 11 + 8);
        assertThat(realmNamed(c, "*").rewrite().any()).isFalse();

        for (String[] bad : new String[][] {
            {"realm.partner.pre-proxy.remove", "No-Such-Attribute", "not a standard attribute"},
            {"realm.partner.pre-proxy.remove", "Cisco-AVPair", "not a standard attribute"},
            {"realm.partner.pre-proxy.remove", "Proxy-State", "managed by the proxy"},
            {"realm.partner.post-proxy.remove", "Message-Authenticator", "managed by the proxy"},
            {"realm.partner.pre-proxy.add", "No-Such = 1", "unknown attribute"},
            {"realm.partner.pre-proxy.add", "NAS-Port = many", "cannot be"},
            {"realm.partner.pre-proxy.add", "garbage", "pre-proxy.add"}
        }) {
            Map<String, String> s = base();
            s.put(bad[0], bad[1]);
            ProxyRewrite rewrite = realmNamed(ProxyConfig.from(Config.of(s)), "partner.example")
                    .rewrite();
            assertThatThrownBy(() -> rewrite.compile(dictionary, "realm partner: "))
                    .as(bad[1])
                    .hasMessageContaining(bad[2]);
        }
    }

    private static ProxyConfig.Realm realmNamed(ProxyConfig c, String name) {
        return c.realms().stream()
                .filter(r -> r.name().equals(name))
                .findFirst()
                .orElseThrow();
    }
}
