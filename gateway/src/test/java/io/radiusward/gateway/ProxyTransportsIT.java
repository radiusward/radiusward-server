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
 * Proxying over plain TCP and DTLS (ADR 0055): gateway A proxies one realm over TCP and another over DTLS to gateway
 * B, which decides from its users file. The TCP realm is rewritten on the way: Calling-Station-Id removed and an
 * Operator-Name added before B sees it (B's check items require both), Class removed from B's answer.
 */
@Epic("Proxying")
@Feature("Proxying over TCP and DTLS")
@Link(
        name = "ADR 0055",
        url =
                "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0055-proxy-transports-and-rewriting.md")
class ProxyTransportsIT {

    static final String TCP_SECRET = "tcp-home-secret";

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

    private int start() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        TestPki.Issued client = pki.client("proxy.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("proxy.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("proxy.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path users = Files.writeString(dir.resolve("home-users"), """
                bob@tcp.example     Cleartext-Password := "pw", Operator-Name == "1op.example", Calling-Station-Id !~ "."
                                    Reply-Message = "over tcp", Class = "home-class"
                carol@dtls.example  Cleartext-Password := "pw"
                                    Reply-Message = "over dtls"
                """);
        Config homeSettings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("radius.tcp.enabled", "true"),
                Map.entry("radius.tcp.auth.port", "0"),
                Map.entry("radius.tcp.acct.port", "0"),
                Map.entry("radsec.dtls.enabled", "true"),
                Map.entry("radsec.dtls.port", "0"),
                Map.entry("radsec.certificate", pki.serverPem.toString()),
                Map.entry("radsec.key", pki.serverKey.toString()),
                Map.entry("radsec.ca", pki.caPem.toString()),
                Map.entry("nas.local.address", "127.0.0.1"),
                Map.entry("nas.local.secret", TCP_SECRET),
                Map.entry("nas.local.tcp", "true"),
                Map.entry("nas.local.dtls", "true")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        home = Gateway.launchWith(
                config("home", 2),
                NasRegistry.from(homeSettings),
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
                Map.entry("proxy.timeout", "1s"),
                Map.entry("proxy.retries", "2"),
                Map.entry("home.t.address", "127.0.0.1:" + home.tcpPort(true)),
                Map.entry("home.t.transport", "tcp"),
                Map.entry("home.t.secret", TCP_SECRET),
                Map.entry("home.d.address", "127.0.0.1:" + home.dtlsPort()),
                Map.entry("home.d.transport", "dtls"),
                Map.entry("home.d.tls.certificate", clientPem.toString()),
                Map.entry("home.d.tls.key", clientKey.toString()),
                Map.entry("home.d.tls.ca", pki.caPem.toString()),
                Map.entry("home.d.tls.name", "radius.home.test"),
                Map.entry("pool.t.servers", "t"),
                Map.entry("pool.d.servers", "d"),
                Map.entry("realm.t.name", "tcp.example"),
                Map.entry("realm.t.pool", "t"),
                Map.entry("realm.t.pre-proxy.remove", "Calling-Station-Id"),
                Map.entry("realm.t.pre-proxy.add", "Operator-Name = \"1op.example\""),
                Map.entry("realm.t.post-proxy.remove", "Class"),
                Map.entry("realm.d.name", "dtls.example"),
                Map.entry("realm.d.pool", "d")));
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
    void overTcpRewrittenAndOverDtls() throws Exception {
        int port = start();
        byte[] tcp = nas.pap("bob@tcp.example", "pw", "aa-bb-cc-00-02-01");
        byte[] accept = nas.send(port, tcp, Duration.ofSeconds(5));
        ProxyIT.assertForTheNas(accept, tcp, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(accept, StandardCharsets.ISO_8859_1)).contains("over tcp");
        assertThat(AuthAgentTest.wrap(accept).findAttribute(25))
                .as("Class removed")
                .isNegative();

        byte[] dtls = nas.pap("carol@dtls.example", "pw", "aa-bb-cc-00-02-02");
        byte[] dtlsAccept = nas.send(port, dtls, Duration.ofSeconds(8));
        ProxyIT.assertForTheNas(dtlsAccept, dtls, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(dtlsAccept, StandardCharsets.ISO_8859_1)).contains("over dtls");

        byte[] wrong = nas.pap("carol@dtls.example", "nope", "aa-bb-cc-00-02-03");
        ProxyIT.assertForTheNas(nas.send(port, wrong, Duration.ofSeconds(5)), wrong, RadiusCode.ACCESS_REJECT);
        assertThat(proxy.metrics())
                .contains("radiusward_gateway_proxy_requests_total{gateway=\"1\",home=\"t\",result=\"accepted\"} 1")
                .contains("radiusward_gateway_proxy_requests_total{gateway=\"1\",home=\"d\",result=\"accepted\"} 1")
                .contains("radiusward_gateway_proxy_requests_total{gateway=\"1\",home=\"d\",result=\"rejected\"} 1");
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
