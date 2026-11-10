/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.radiusward.common.config.Config;
import io.radiusward.radius.codec.RadiusCode;
import java.io.File;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An IPv6 NAS (ADR 0047): the gateway listens on {@code ::}, the NAS entry is {@code ::1}, and an Access-Request from
 * {@code [::1]} is answered with that entry's secret; the same gateway still answers its IPv4 NAS.
 */
class Ipv6IT {

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
    void aNasOnIpv6IsAnswered() throws Exception {
        InetAddress loopback6 = InetAddress.getByName("::1");
        try (DatagramSocket probe = new DatagramSocket(new InetSocketAddress(loopback6, 0))) {
            assumeTrue(probe.isBound(), "no IPv6 loopback");
        } catch (java.net.SocketException e) {
            assumeTrue(false, "no IPv6 loopback");
        }
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Config config = Config.of(Map.of(
                "auth.stores", "local",
                "auth.store.local.type", "file",
                "auth.store.local.path", users.toString(),
                "auth.plugins.dir", dir.resolve("no-plugins").toString(),
                "nas.six.address", "::1",
                "nas.six.secret", "six-secret",
                "nas.four.address", "127.0.0.1",
                "nas.four.secret", new String(AuthAgentTest.SECRET, StandardCharsets.US_ASCII)));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        GatewayConfig c = UdpAgentTest.config(Duration.ZERO, 1024);
        gateway = Gateway.launchWith(
                new GatewayConfig(
                        c.gatewayId(),
                        "::",
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
                NasRegistry.from(config),
                auth,
                Gateway.storeHandler(config, auth));

        byte[] six = "six-secret".getBytes(StandardCharsets.US_ASCII);
        byte[] request = AuthAgentTest.accessRequest(1, "arctangent", true, false, six);
        AuthAgentTest.assertSignedReplyTo(exchange(loopback6, request), request, RadiusCode.ACCESS_ACCEPT, six);
        byte[] again = AuthAgentTest.accessRequest(2, "wrong", true, false, six);
        AuthAgentTest.assertSignedReplyTo(exchange(loopback6, again), again, RadiusCode.ACCESS_REJECT, six);

        byte[] four = AuthAgentTest.accessRequest(3, "arctangent", true, false);
        AuthAgentTest.assertSignedReplyTo(
                exchange(InetAddress.getByName("127.0.0.1"), four), four, RadiusCode.ACCESS_ACCEPT);
    }

    private byte[] exchange(InetAddress from, byte[] request) throws Exception {
        try (DatagramSocket nas = new DatagramSocket(new InetSocketAddress(from, 0))) {
            nas.setSoTimeout(3_000);
            nas.send(new DatagramPacket(request, request.length, from, gateway.authPort()));
            byte[] in = new byte[4096];
            DatagramPacket p = new DatagramPacket(in, in.length);
            nas.receive(p);
            assertThat(p.getAddress()).isEqualTo(from);
            return Arrays.copyOf(in, p.getLength());
        }
    }
}
