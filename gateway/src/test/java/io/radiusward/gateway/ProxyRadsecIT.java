/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proxying over RadSec (ADR 0037, milestone 4): gateway A proxies a realm to gateway B, its home server, over TLS
 * with a client certificate; B decides from its own store. The NAS talks UDP to A and gets B's answer, signed for it.
 * A home server whose certificate does not carry the expected name gets nothing.
 */
@Epic("Proxying")
@Feature("Proxying over RadSec")
@Link(name = "ADR 0037", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0037-proxying.md")
class ProxyRadsecIT {

    @TempDir
    Path dir;

    private Gateway home;
    private Gateway proxy;
    private final ProxyIT nas = new ProxyIT();

    @AfterEach
    void stop() throws Exception {
        nas.stop();
        for (Gateway g : new Gateway[] {proxy, home}) {
            if (g != null) {
                g.close();
            }
        }
    }

    private int start(String expectedName) throws Exception {
        TestPki pki = new TestPki(dir, "home");
        TestPki.Issued client = pki.client("proxy.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("proxy.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("proxy.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path users = Files.writeString(dir.resolve("home-users"), """
                alice@partner.example  Cleartext-Password := "home-pw"
                                       Reply-Message = "decided at home"
                """);
        Config homeSettings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("radsec.enabled", "true"),
                Map.entry("radsec.port", "0"),
                Map.entry("radsec.certificate", pki.serverPem.toString()),
                Map.entry("radsec.key", pki.serverKey.toString()),
                Map.entry("radsec.ca", pki.caPem.toString()),
                Map.entry("nas.local.radsec", "true"),
                Map.entry("nas.local.radsec.identity", "proxy.corp.test")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        home = Gateway.launchWith(
                config("home", 2),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(homeSettings, auth),
                RadsecConfig.from(homeSettings, "127.0.0.1"));

        Map<String, String> proxySettings = new HashMap<>(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry(
                        "auth.store.local.path",
                        Files.writeString(dir.resolve("none"), "").toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.timeout", "500ms"),
                Map.entry("proxy.retries", "1"),
                Map.entry("home.b.address", "127.0.0.1:" + home.radsecPort()),
                Map.entry("home.b.transport", "tls"),
                Map.entry("home.b.tls.certificate", clientPem.toString()),
                Map.entry("home.b.tls.key", clientKey.toString()),
                Map.entry("home.b.tls.ca", pki.caPem.toString()),
                Map.entry("home.b.tls.name", expectedName),
                Map.entry("pool.partner.servers", "b"),
                Map.entry("realm.partner.name", "partner.example"),
                Map.entry("realm.partner.pool", "partner")));
        Config config = Config.of(proxySettings);
        proxy = Gateway.launchWith(
                config("proxy", 1),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(config, auth),
                RadsecConfig.DISABLED,
                CoaConfig.DISABLED,
                ProxyConfig.from(config));
        return proxy.authPort();
    }

    @Test
    void theHomeServerDecidesOverTls() throws Exception {
        int port = start("radius.home.test");
        byte[] good = nas.pap("alice@partner.example", "home-pw", "aa-bb-cc-00-01-01");
        byte[] accept = nas.send(port, good, Duration.ofSeconds(5));
        ProxyIT.assertForTheNas(accept, good, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(accept, StandardCharsets.ISO_8859_1)).contains("decided at home");

        byte[] wrong = nas.pap("alice@partner.example", "wrong", "aa-bb-cc-00-01-02");
        ProxyIT.assertForTheNas(nas.send(port, wrong, Duration.ofSeconds(5)), wrong, RadiusCode.ACCESS_REJECT);
        assertThat(proxy.metrics())
                .contains("radiusward_gateway_proxy_requests_total{gateway=\"1\",home=\"b\",result=\"accepted\"} 1")
                .contains("radiusward_gateway_proxy_requests_total{gateway=\"1\",home=\"b\",result=\"rejected\"} 1");
    }

    @Test
    void aHomeServerWithAnotherNameGetsNothing() throws Exception {
        int port = start("someone-else.test");
        byte[] request = nas.pap("alice@partner.example", "home-pw", "aa-bb-cc-00-01-03");
        assertThat(nas.send(port, request, Duration.ofSeconds(2))).isNull();
        assertThat(home.radsecAgent().get(RadsecAgent.Counter.REQUESTS)).isZero();
    }

    private GatewayConfig config(String name, int id) {
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new GatewayConfig(
                id,
                c.listenHost(),
                0,
                c.socketReceiveBuffer(),
                c.clusterMembers(),
                c.clusterBasePort(),
                c.egressHost(),
                c.profile(),
                c.pendingCapacity(),
                c.pendingTimeout(),
                c.resubmitAfter(),
                c.responseCacheTtl(),
                c.dedicatedThreads(),
                c.idleStrategy(),
                new File(dir.toFile(), "aeron-" + name).getPath(),
                c.dictionaryDir(),
                c.debugResponseDelay());
    }
}
