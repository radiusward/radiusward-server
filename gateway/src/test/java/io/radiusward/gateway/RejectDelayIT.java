/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.RadiusCode;
import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Access-Rejects held back (ADR 0057) and the authentication log (ADR 0058) on a running gateway: a reject arrives
 * after the delay, an accept at once, a retransmission during the delay gets no second answer; both decisions are
 * logged with the reject's cause.
 */
@Epic("Authentication")
@Feature("Reject delay and authentication log")
@Link(
        name = "ADR 0057",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0057-reject-delay.md")
@Link(
        name = "ADR 0058",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0058-authentication-log.md")
class RejectDelayIT {

    @TempDir
    Path dir;

    private Gateway gateway;

    @AfterEach
    void stop() {
        if (gateway != null) {
            gateway.close();
        }
    }

    @Test
    void rejectsWaitAndEverythingIsLogged() throws Exception {
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Config config = Config.of(Map.of(
                "auth.stores",
                "local",
                "auth.store.local.type",
                "file",
                "auth.store.local.path",
                users.toString(),
                "auth.plugins.dir",
                dir.resolve("no-plugins").toString(),
                "auth.reject.delay",
                "400ms",
                "auth.log.dir",
                dir.resolve("log").toString()));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        gateway = Gateway.launchWith(
                new GatewayConfig(
                        c.gatewayId(),
                        "127.0.0.1",
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
                        c.debugResponseDelay()),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF),
                auth,
                Gateway.storeHandler(config, auth));
        gateway.rejectDelay(Gateway.rejectDelay(config));
        gateway.authLog(config);

        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (DatagramSocket nas = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            nas.setSoTimeout(3_000);
            byte[] good = AuthAgentTest.accessRequest(1, "arctangent", true, false);
            long start = System.nanoTime();
            AuthAgentTest.assertSignedReplyTo(exchange(nas, good), good, RadiusCode.ACCESS_ACCEPT);
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(300));

            byte[] wrong = AuthAgentTest.accessRequest(2, "wrong", true, false);
            start = System.nanoTime();
            nas.send(new DatagramPacket(wrong, wrong.length, loopback, gateway.authPort()));
            Thread.sleep(100);
            nas.send(new DatagramPacket(wrong, wrong.length, loopback, gateway.authPort())); // retransmitted
            AuthAgentTest.assertSignedReplyTo(receive(nas), wrong, RadiusCode.ACCESS_REJECT);
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isGreaterThanOrEqualTo(Duration.ofMillis(380));
            nas.setSoTimeout(300);
            assertThatThrownBy(() -> receive(nas))
                    .as("one answer for both copies")
                    .isInstanceOf(SocketTimeoutException.class);
        }
        long deadline = System.nanoTime() + 5_000_000_000L;
        Path day = dir.resolve("log");
        List<String> lines = List.of();
        while (System.nanoTime() < deadline && lines.size() < 2) {
            try (var files = Files.list(day)) {
                lines = files.flatMap(f -> {
                            try {
                                return Files.readAllLines(f).stream();
                            } catch (java.io.IOException e) {
                                throw new java.io.UncheckedIOException(e);
                            }
                        })
                        .toList();
            } catch (java.nio.file.NoSuchFileException e) {
                lines = List.of();
            }
            Thread.sleep(20);
        }
        assertThat(lines).hasSize(2);
        assertThat(lines.get(0)).contains("\"user\":\"nemo\"", "\"result\":\"accept\"");
        assertThat(lines.get(1)).contains("\"result\":\"reject\"", "\"reason\":\"credentials or method rejected\"");
        assertThat(gateway.metrics()).contains("result=\"rejects_delayed\"} 1");

        assertThatThrownBy(() -> Gateway.rejectDelay(Config.of(Map.of("auth.reject.delay", "6s"))))
                .isInstanceOf(ConfigException.class);
        assertThat(Gateway.rejectDelay(Config.of(Map.of()))).isEqualTo(Duration.ofSeconds(1));
    }

    private byte[] exchange(DatagramSocket nas, byte[] request) throws Exception {
        nas.send(new DatagramPacket(request, request.length, InetAddress.getByName("127.0.0.1"), gateway.authPort()));
        return receive(nas);
    }

    private static byte[] receive(DatagramSocket nas) throws Exception {
        byte[] in = new byte[4096];
        DatagramPacket p = new DatagramPacket(in, in.length);
        nas.receive(p);
        return Arrays.copyOf(in, p.getLength());
    }
}
