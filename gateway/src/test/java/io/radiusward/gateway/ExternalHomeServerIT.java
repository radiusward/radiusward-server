/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

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
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The gateway proxying to an external RADIUS server over UDP (ADR 0037, milestone 7): an implementation we did not
 * write decrypts the User-Password we re-encrypted, checks our Message-Authenticator, and its answers — Accept with a
 * Reply-Message, Reject — must pass our checks and reach the NAS signed for it; it also answers our Status-Server.
 * Runs only with {@code -Pinterop} and an installed {@code radiusd}.
 */
@Epic("Proxying")
@Feature("Interop with another RADIUS server")
@Link(name = "ADR 0037", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0037-proxying.md")
class ExternalHomeServerIT {

    @TempDir
    Path dir;

    private ExternalRadiusServer home;
    private Gateway gateway;
    private final ProxyIT nas = new ProxyIT();

    @AfterEach
    void stop() throws Exception {
        nas.stop();
        if (gateway != null) {
            gateway.close();
        }
        if (home != null) {
            home.stop("external-home-server");
        }
    }

    @Test
    void theExternalServerDecides() throws Exception {
        assumeTrue(Boolean.getBoolean("radiusward.interop"), "interop profile not active");
        Optional<Path> binary = ExternalRadiusServer.binary();
        assumeTrue(binary.isPresent(), "no radiusd installed");
        int port = ExternalRadiusServer.freeUdpPort();
        Path serverDir = Files.createDirectories(dir.resolve("home"));
        Path users = Files.writeString(serverDir.resolve("users"), """
                alice@partner.example  Cleartext-Password := "home-pw"
                                       Reply-Message = "external home"
                """);
        home = ExternalRadiusServer.start(binary.get(), serverDir, """
                modules {
                    pap {
                    }
                    files {
                        filename = %1$s
                    }
                }
                client proxy {
                    ipaddr = 127.0.0.1
                    secret = home-secret
                    require_message_authenticator = yes
                }
                server default {
                    listen {
                        type = auth
                        ipaddr = 127.0.0.1
                        port = %2$d
                    }
                    authorize {
                        files
                        pap
                    }
                    authenticate {
                        Auth-Type PAP {
                            pap
                        }
                    }
                }
                """.formatted(users, port));
        Config settings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry(
                        "auth.store.local.path",
                        Files.writeString(dir.resolve("none"), "").toString()),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("proxy.enabled", "true"),
                Map.entry("proxy.timeout", "1s"),
                Map.entry("proxy.status.interval", "1s"),
                Map.entry("home.ext.address", "127.0.0.1:" + port),
                Map.entry("home.ext.secret", "home-secret"),
                Map.entry("pool.ext.servers", "ext"),
                Map.entry("realm.partner.name", "partner.example"),
                Map.entry("realm.partner.pool", "ext")));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        gateway = Gateway.launchWith(
                config(),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                auth,
                Gateway.storeHandler(settings, auth),
                RadsecConfig.DISABLED,
                CoaConfig.DISABLED,
                ProxyConfig.from(settings));
        int gw = gateway.authPort();

        byte[] good = nas.pap("alice@partner.example", "home-pw", "aa-bb-cc-00-05-01");
        byte[] accept = nas.send(gw, good, Duration.ofSeconds(5));
        ProxyIT.assertForTheNas(accept, good, RadiusCode.ACCESS_ACCEPT);
        assertThat(new String(accept, StandardCharsets.ISO_8859_1)).contains("external home");

        byte[] wrong = nas.pap("alice@partner.example", "wrong", "aa-bb-cc-00-05-02");
        ProxyIT.assertForTheNas(nas.send(gw, wrong, Duration.ofSeconds(5)), wrong, RadiusCode.ACCESS_REJECT);

        Thread.sleep(1500); // a Status-Server round
        assertThat(Files.readString(serverDir.resolve("server.log"))).contains("Status-Server");
        assertThat(gateway.metrics()).contains("radiusward_gateway_proxy_home_alive{gateway=\"1\",home=\"ext\"} 1");
    }

    private GatewayConfig config() {
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        return new GatewayConfig(
                c.gatewayId(),
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
                new File(dir.toFile(), "aeron").getPath(),
                c.dictionaryDir(),
                c.debugResponseDelay());
    }
}
