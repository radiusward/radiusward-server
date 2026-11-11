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
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Inner tunnel credentials checked by home servers over RadSec and plain TCP (ADR 0044, 0055): a gateway with RadSec
 * and TCP listeners is the home server of two realms; the inner proxy's verdicts come back over both.
 */
@Epic("Proxying")
@Feature("Inner-tunnel proxying")
@Link(
        name = "ADR 0044",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0044-inner-tunnel-proxying.md")
@Link(
        name = "ADR 0055",
        url =
                "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0055-proxy-transports-and-rewriting.md")
class InnerProxyStreamIT {

    @TempDir
    Path dir;

    private Gateway home;

    @AfterEach
    void stop() {
        if (home != null) {
            home.close();
        }
    }

    @Test
    void innerCredentialsOverRadsecAndTcp() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        TestPki.Issued client = pki.client("proxy.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("proxy.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("proxy.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path users = Files.writeString(dir.resolve("home-users"), """
                bob@tls.example  Cleartext-Password := "pw"
                                 Reply-Message = "inner over tls"
                eve@tcp.example  Cleartext-Password := "pw"
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
                Map.entry("radius.tcp.enabled", "true"),
                Map.entry("radius.tcp.auth.port", "0"),
                Map.entry("radius.tcp.acct.port", "0"),
                Map.entry("nas.local.address", "127.0.0.1"),
                Map.entry("nas.local.secret", "tcp-home-secret"),
                Map.entry("nas.local.tcp", "true"),
                Map.entry("nas.local.radsec", "true"),
                Map.entry("nas.local.radsec.identity", "proxy.corp.test")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        home = Gateway.launchWith(
                new GatewayConfig(
                        2,
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
                        new File(dir.toFile(), "aeron-home").getPath(),
                        c.dictionaryDir(),
                        c.debugResponseDelay()),
                NasRegistry.from(homeSettings),
                auth,
                Gateway.storeHandler(homeSettings, auth),
                RadsecConfig.from(homeSettings, "127.0.0.1"));

        InnerProxy proxy = new InnerProxy(ProxyConfig.from(Config.of(Map.ofEntries(
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.inner", "true"),
                Map.entry("proxy.timeout", "2s"),
                Map.entry("proxy.retries", "0"),
                Map.entry("home.s.address", "127.0.0.1:" + home.radsecPort()),
                Map.entry("home.s.transport", "tls"),
                Map.entry("home.s.tls.certificate", clientPem.toString()),
                Map.entry("home.s.tls.key", clientKey.toString()),
                Map.entry("home.s.tls.ca", pki.caPem.toString()),
                Map.entry("home.s.tls.name", "radius.home.test"),
                Map.entry("home.t.address", "127.0.0.1:" + home.tcpPort(true)),
                Map.entry("home.t.transport", "tcp"),
                Map.entry("home.t.secret", "tcp-home-secret"),
                Map.entry("pool.s.servers", "s"),
                Map.entry("pool.t.servers", "t"),
                Map.entry("realm.s.name", "tls.example"),
                Map.entry("realm.s.pool", "s"),
                Map.entry("realm.t.name", "tcp.example"),
                Map.entry("realm.t.pool", "t")))));

        InnerProxy.Result tls = proxy.password("bob@tls.example", "pw".getBytes(StandardCharsets.US_ASCII));
        assertThat(tls.inner().code()).isEqualTo(AccessHandler.ACCEPT);
        assertThat(new String(tls.reply(), StandardCharsets.ISO_8859_1)).contains("inner over tls");
        assertThat(proxy.password("bob@tls.example", "no".getBytes(StandardCharsets.US_ASCII))
                        .inner()
                        .code())
                .isEqualTo(AccessHandler.REJECT);
        assertThat(proxy.password("eve@tcp.example", "pw".getBytes(StandardCharsets.US_ASCII))
                        .inner()
                        .code())
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(proxy.get(InnerProxy.Counter.ACCEPTED)).isEqualTo(2);
    }
}
