/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
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
 * Dynamic discovery (RFC 7585, ADR 0037, milestone 6): a realm's RadSec home server found in DNS — NAPTR
 * {@code aaa+auth:radius.tls.tcp}, SRV, A — from a test DNS server. The first request starts the lookup and is not
 * answered; the NAS's retransmission gets the home server's answer. A realm publishing nothing gets no answer, and DNS
 * is not asked again before the negative TTL.
 */
class ProxyDiscoveryIT {

    @TempDir
    Path dir;

    private Gateway home;
    private Gateway proxy;
    private TestDns dns;
    private final ProxyIT nas = new ProxyIT();

    @AfterEach
    void stop() throws Exception {
        nas.stop();
        for (Gateway g : new Gateway[] {proxy, home}) {
            if (g != null) {
                g.close();
            }
        }
        if (dns != null) {
            dns.close();
        }
    }

    @Test
    void theRealmsHomeServerIsFoundInDns() throws Exception {
        TestPki pki = new TestPki(dir, "home");
        TestPki.Issued client = pki.client("proxy.corp.test");
        Path clientPem = TestPki.write(
                dir.resolve("proxy.pem"), "CERTIFICATE", client.certificate().getEncoded());
        Path clientKey = TestPki.write(
                dir.resolve("proxy.key"),
                "PRIVATE KEY",
                client.keys().getPrivate().getEncoded());
        Path users = Files.writeString(dir.resolve("home-users"), """
                alice@roam.example  Cleartext-Password := "roam-pw"
                                    Reply-Message = "found you"
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
                Map.entry("nas.local.radsec", "true")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        home = Gateway.launchWith(
                config("home", 2),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(homeSettings, auth),
                RadsecConfig.from(homeSettings, "127.0.0.1"));

        dns = new TestDns()
                .naptr("roam.example", 100, 10, "s", RealmDiscovery.SERVICE, "_radsec._tcp.roam.example")
                .naptr("roam.example", 50, 10, "s", "aaa+auth:radius.dtls.udp", "_radsec._udp.roam.example")
                .srv("_radsec._tcp.roam.example", 0, 10, home.radsecPort(), "radius.home.test")
                .a("radius.home.test", new byte[] {127, 0, 0, 1});

        Config settings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry(
                        "auth.store.local.path",
                        Files.writeString(dir.resolve("none"), "").toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.timeout", "500ms"),
                Map.entry("proxy.retries", "1"),
                Map.entry("realm.roam.name", "roam.example"),
                Map.entry("realm.roam.discover", "true"),
                Map.entry("realm.nowhere.name", "nowhere.example"),
                Map.entry("realm.nowhere.discover", "true"),
                Map.entry("proxy.discovery.dns.server", dns.server()),
                Map.entry("proxy.discovery.tls.certificate", clientPem.toString()),
                Map.entry("proxy.discovery.tls.key", clientKey.toString()),
                Map.entry("proxy.discovery.tls.ca", pki.caPem.toString())));
        proxy = Gateway.launchWith(
                config("proxy", 1),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(settings, auth),
                RadsecConfig.DISABLED,
                CoaConfig.DISABLED,
                ProxyConfig.from(settings));
        int port = proxy.authPort();

        byte[] request = nas.pap("alice@roam.example", "roam-pw", "aa-bb-cc-00-03-01");
        byte[] answer = null;
        for (int attempt = 0; attempt < 6 && answer == null; attempt++) { // the NAS retransmits
            answer = nas.send(port, request, Duration.ofSeconds(1));
        }
        ProxyIT.assertForTheNas(answer, request, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(answer, StandardCharsets.ISO_8859_1)).contains("found you");

        int before = dns.queries.get();
        byte[] nowhere = nas.pap("bob@nowhere.example", "x", "aa-bb-cc-00-03-02");
        for (int attempt = 0; attempt < 3; attempt++) {
            assertThat(nas.send(port, nowhere, Duration.ofMillis(500))).isNull();
        }
        assertThat(dns.queries.get() - before)
                .as("one NAPTR query, then the negative cache")
                .isEqualTo(1);
    }

    @Test
    void naptrRecordsAreParsed() {
        assertThat(RealmDiscovery.fields("100 10 \"s\" \"aaa+auth:radius.tls.tcp\" \"\" _radsec._tcp.roam.example."))
                .containsExactly("100", "10", "s", "aaa+auth:radius.tls.tcp", "", "_radsec._tcp.roam.example.");
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
