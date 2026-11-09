/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusCode;
import java.io.File;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The real gateway with authentication on: its own threads, four workers sharing the queue, concurrent clients.
 * No cluster is needed for Access-Requests.
 */
class GatewayAuthIT {

    @TempDir
    Path dir;

    @Test
    void concurrentClientsGetTheirOwnSignedReplies() throws Exception {
        AtomicInteger decided = new AtomicInteger();
        AccessHandler handler = context -> {
            decided.incrementAndGet();
            UnsafeBuffer password = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
            int n = context.credentials()
                    .decryptUserPassword(context.request(), context.nas().secret(), password, 0);
            LockSupportSleep.millis(1); // a store look-up
            return n == 10 ? AccessHandler.ACCEPT : AccessHandler.REJECT;
        };
        GatewayConfig config = UdpAgentTest.config(Duration.ZERO, 1024);
        GatewayConfig withDir = new GatewayConfig(
                config.gatewayId(),
                config.listenHost(),
                0,
                config.socketReceiveBuffer(),
                config.clusterMembers(),
                config.clusterBasePort(),
                config.egressHost(),
                config.profile(),
                config.pendingCapacity(),
                config.pendingTimeout(),
                config.resubmitAfter(),
                config.responseCacheTtl(),
                config.dedicatedThreads(),
                config.idleStrategy(),
                new File(dir.toFile(), "aeron").getPath(),
                config.dictionaryDir(),
                config.debugResponseDelay());
        try (Gateway gateway = Gateway.launch(
                withDir,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                new AuthConfig(true, 0, 4, 256, 4096, Duration.ofSeconds(10)),
                handler)) {
            int port = gateway.authPort();
            int clients = 8;
            int perClient = 250;
            List<CompletableFuture<Integer>> runs = new ArrayList<>();
            for (int c = 0; c < clients; c++) {
                runs.add(CompletableFuture.supplyAsync(() -> exchange(port, perClient)));
            }
            int answered = runs.stream().mapToInt(CompletableFuture::join).sum();
            assertThat(answered).isEqualTo(clients * perClient);
            AuthStats stats = gateway.authStats();
            assertThat(stats.get(AuthStats.Counter.ACCEPTED) + stats.get(AuthStats.Counter.REJECTED))
                    .isEqualTo(decided.get());
            assertThat(stats.get(AuthStats.Counter.REJECTED)).isEqualTo(clients * perClient / 2);
            assertThat(gateway.metrics())
                    .contains("radiusward_gateway_access_requests_total{gateway=\"1\",result=\"accepted\"}");
            assertThat(gateway.stateJson()).contains("\"access\":{");
        }
    }

    /** One client: alternating good and wrong passwords, each reply checked against its own request. */
    private static int exchange(int port, int count) {
        try (DatagramChannel channel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
            channel.connect(new InetSocketAddress("127.0.0.1", port));
            channel.socket().setSoTimeout(5_000);
            int ok = 0;
            ByteBuffer in = ByteBuffer.allocate(4096);
            for (int i = 0; i < count; i++) {
                boolean good = i % 2 == 0;
                byte[] request = AuthAgentTest.accessRequest(i & 0xFF, good ? "arctangent" : "wrong", true, false);
                byte[] reply = null;
                for (int attempt = 0; attempt < 5 && reply == null; attempt++) {
                    channel.write(ByteBuffer.wrap(request));
                    long deadline = System.nanoTime() + 2_000_000_000L;
                    while (reply == null && System.nanoTime() < deadline) {
                        in.clear();
                        channel.configureBlocking(false);
                        if (channel.read(in) > 0 && in.get(1) == request[1]) {
                            reply = java.util.Arrays.copyOf(in.array(), in.position());
                        } else {
                            Thread.sleep(1);
                        }
                    }
                }
                AuthAgentTest.assertSignedReplyTo(
                        reply, request, good ? RadiusCode.ACCESS_ACCEPT : RadiusCode.ACCESS_REJECT);
                ok++;
            }
            return ok;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class LockSupportSleep {
        static void millis(long ms) {
            java.util.concurrent.locks.LockSupport.parkNanos(ms * 1_000_000);
        }
    }
}
