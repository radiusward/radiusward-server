/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.common.config.Config;
import io.radiusward.gateway.AuthConfig;
import io.radiusward.gateway.Gateway;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Simultaneous use across two gateways and a three-member cluster (ADR 0023): the limit holds whichever gateway a
 * device uses, a reservation keeps the place between Accept and Accounting-Start, and a Stop frees it.
 */
@Epic("Authentication")
@Feature("Simultaneous-Use")
@Link(
        name = "ADR 0023",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0023-simultaneous-use.md")
class SimultaneousUseIT {

    static final byte[] SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);
    static final String A = "AA-BB-CC-00-00-01";
    static final String B = "AA-BB-CC-00-00-02";

    @TempDir
    Path dir;

    private LocalCluster cluster;
    private DatagramChannel nas;
    private int identifier;

    @AfterEach
    void stop() throws Exception {
        if (nas != null) {
            nas.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }

    @Test
    void oneDeviceAtATimeWhicheverGatewayItUses() throws Exception {
        Path users = Files.writeString(
                dir.resolve("users"),
                "alice Cleartext-Password := \"pw\", Simultaneous-Use := 1\nbob Cleartext-Password := \"pw\"\n");
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        Config stores = Config.of(Map.of(
                "auth.stores",
                "local",
                "auth.store.local.type",
                "file",
                "auth.store.local.path",
                users.toString(),
                "auth.plugins.dir",
                dir.resolve("plugins").toString()));
        AuthConfig auth = new AuthConfig(
                true, 0, 2, 256, 4096, Duration.ofSeconds(10), Duration.ofSeconds(2), Duration.ofSeconds(30));
        Gateway g0 = cluster.startGateway(1, 0, LocalCluster.registry(), auth, Gateway.storeHandler(stores, auth));
        Gateway g1 = cluster.startGateway(2, 0, LocalCluster.registry(), auth, Gateway.storeHandler(stores, auth));
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();

        int supported = io.radiusward.cluster.service.AccountingStateMachine.STATE_VERSION;
        exchangeAccounting(g0, accounting(1, "warm-up", "nobody", null)); // the log needs a recording to report
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "state version 6 activated",
                    () -> admin.state().activeVersion() >= 6);
        }
        assertThat(supported).isGreaterThanOrEqualTo(6);

        assertThat(access(g0, "alice", "pw", A)).as("first device").isEqualTo(RadiusCode.ACCESS_ACCEPT);
        assertThat(access(g1, "alice", "pw", B)).as("A holds the only place").isEqualTo(RadiusCode.ACCESS_REJECT);
        assertThat(access(g1, "alice", "pw", A)).as("the same device again").isEqualTo(RadiusCode.ACCESS_ACCEPT);
        assertThat(access(g0, "bob", "pw", B)).as("no limit").isEqualTo(RadiusCode.ACCESS_ACCEPT);

        exchangeAccounting(
                g0,
                accounting(
                        1, "s-alice", "Alice",
                        A)); // A comes online (accounting may spell the name differently): its reservation ends
        assertThat(access(g0, "alice", "pw", B)).isEqualTo(RadiusCode.ACCESS_REJECT);
        exchangeAccounting(g1, accounting(2, "s-alice", "alice", A)); // Stop
        assertThat(access(g1, "alice", "pw", B)).as("A went offline").isEqualTo(RadiusCode.ACCESS_ACCEPT);
        assertThat(access(g0, "alice", "pw", "")).as("B is reserved now").isEqualTo(RadiusCode.ACCESS_REJECT);

        cluster.awaitConverged(); // every member counted alike
    }

    /**
     * {@code coa.simultaneous.use = disconnect-oldest} (ADR 0036): over the limit, the oldest session gets a
     * Disconnect-Request; its NAS acknowledges and sends the Accounting-Stop, and the new device is let in.
     */
    @Test
    void theOldestSessionIsDisconnectedInsteadOfTheNewOneRejected() throws Exception {
        Path users =
                Files.writeString(dir.resolve("users"), "alice Cleartext-Password := \"pw\", Simultaneous-Use := 1\n");
        DatagramChannel coaNas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        java.util.List<String> disconnected = new java.util.concurrent.CopyOnWriteArrayList<>();
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        Config settings = Config.of(Map.of(
                "auth.stores",
                "local",
                "auth.store.local.type",
                "file",
                "auth.store.local.path",
                users.toString(),
                "auth.plugins.dir",
                dir.resolve("plugins").toString(),
                "coa.enabled",
                "true",
                "coa.simultaneous.use",
                "disconnect-oldest",
                "coa.timeout",
                "500ms",
                "nas." + LocalCluster.NAS_NAME + ".coa.port",
                Integer.toString(((InetSocketAddress) coaNas.getLocalAddress()).getPort())));
        AuthConfig auth = new AuthConfig(
                true, 0, 2, 256, 4096, Duration.ofSeconds(10), Duration.ofSeconds(2), Duration.ofSeconds(30));
        Gateway g0 = cluster.startGateway(
                1,
                0,
                LocalCluster.registry(),
                auth,
                Gateway.storeHandler(settings, auth),
                io.radiusward.gateway.RadsecConfig.DISABLED,
                io.radiusward.gateway.CoaConfig.from(settings));
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        exchangeAccounting(g0, accounting(1, "warm-up", "nobody", null));
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "state version 7",
                    () -> admin.state().activeVersion() >= 7);
        }

        // the NAS: acknowledges a Disconnect-Request, then reports the session's end like a real one
        java.util.concurrent.CompletableFuture<Void> nasThread = java.util.concurrent.CompletableFuture.runAsync(() -> {
            try (DatagramChannel accounting = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
                ByteBuffer in = ByteBuffer.allocate(4096);
                InetSocketAddress from = (InetSocketAddress) coaNas.receive(in);
                byte[] request = Arrays.copyOf(in.array(), in.position());
                String session = CoaIT.attribute(request, 44);
                disconnected.add(session);
                coaNas.send(ByteBuffer.wrap(CoaIT.ack(request, SECRET)), from);
                byte[] stop = accounting(2, session, "alice", A);
                accounting.send(ByteBuffer.wrap(stop), new InetSocketAddress("127.0.0.1", g0.radiusPort()));
                accounting.receive(ByteBuffer.allocate(4096));
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
        try {
            assertThat(access(g0, "alice", "pw", A)).isEqualTo(RadiusCode.ACCESS_ACCEPT);
            exchangeAccounting(g0, accounting(1, "s-alice-a", "alice", A)); // A online
            assertThat(access(g0, "alice", "pw", B))
                    .as("B gets in: A was disconnected")
                    .isEqualTo(RadiusCode.ACCESS_ACCEPT);
            nasThread.get(10, java.util.concurrent.TimeUnit.SECONDS);
            assertThat(disconnected).containsExactly("s-alice-a");
            assertThat(g0.metrics())
                    .contains("radiusward_gateway_simultaneous_use_disconnects_total{gateway=\"1\","
                            + "result=\"acknowledged\"} 1");
        } finally {
            coaNas.close();
        }
    }

    private int access(Gateway gateway, String user, String password, String station) throws Exception {
        byte[] auth = new byte[16];
        ThreadLocalRandom.current().nextBytes(auth);
        byte[] plain = password.getBytes(StandardCharsets.US_ASCII);
        UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests()
                .encryptUserPassword(
                        new UnsafeBuffer(plain), 0, plain.length, new UnsafeBuffer(auth), 0, SECRET, cipher, 0);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, ++identifier & 0xFF)
                .authenticator(auth)
                .attribute(1, user)
                .attribute(2, cipher, 0, n);
        if (!station.isEmpty()) {
            enc.attribute(31, station);
        }
        int ma = enc.messageAuthenticator();
        int length = enc.finish();
        new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, SECRET);
        return exchange(gateway.authPort(), Arrays.copyOf(buffer.byteArray(), length))[0] & 0xFF;
    }

    private byte[] accounting(int status, String sessionId, String user, String station) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, ++identifier & 0xFF)
                .uint32(40, status)
                .attribute(44, sessionId)
                .attribute(1, user)
                .uint32(55, 1_780_000_000L + identifier);
        if (station != null) {
            enc.attribute(31, station);
        }
        if (status == 2) {
            enc.uint32(46, 60);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    private void exchangeAccounting(Gateway gateway, byte[] request) throws Exception {
        assertThat(exchange(gateway.radiusPort(), request)[0] & 0xFF).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
    }

    /** Sends like a NAS (retransmitting from one source port) and returns the reply to this identifier. */
    private byte[] exchange(int port, byte[] request) throws Exception {
        if (nas == null) {
            nas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
            nas.configureBlocking(false);
        }
        InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);
        ByteBuffer in = ByteBuffer.allocate(4096);
        for (int attempt = 0; attempt < 8; attempt++) {
            nas.send(ByteBuffer.wrap(request), target);
            long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
            while (System.nanoTime() < deadline) {
                in.clear();
                if (nas.receive(in) != null && in.get(1) == request[1]) {
                    return Arrays.copyOf(in.array(), in.position());
                }
                Thread.sleep(2);
            }
        }
        throw new AssertionError("no reply");
    }
}
