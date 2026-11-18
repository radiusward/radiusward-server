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
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.server.AuthConfig;
import io.radiusward.server.RadiusServer;
import io.radiusward.testing.packets.TestPacket;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Simultaneous use across two RADIUS servers and a three-member cluster (ADR 0023): the limit holds whichever RADIUS server a
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
    private final FakeNas nas = new FakeNas();
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
    void oneDeviceAtATimeWhicheverServerItUses() throws Exception {
        Path users = Files.writeString(
                dir.resolve("users"),
                "alice Cleartext-Password := \"pw\", Simultaneous-Use := 1\nbob Cleartext-Password := \"pw\"\n");
        cluster = LocalCluster.builder(dir.resolve("cluster").toFile())
                .members(3)
                .radiusServers(0)
                .purge(new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)))
                .start();
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
        RadiusServer g0 =
                cluster.startServer(1, 0, LocalCluster.registry(), auth, RadiusServer.storeHandler(stores, auth));
        RadiusServer g1 =
                cluster.startServer(2, 0, LocalCluster.registry(), auth, RadiusServer.storeHandler(stores, auth));
        cluster.awaitLeader();
        cluster.awaitServersConnected();

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
        cluster = LocalCluster.builder(dir.resolve("cluster").toFile())
                .members(3)
                .radiusServers(0)
                .purge(new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)))
                .start();
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
        RadiusServer g0 = cluster.startServer(
                1,
                0,
                LocalCluster.registry(),
                auth,
                RadiusServer.storeHandler(settings, auth),
                io.radiusward.server.RadsecConfig.DISABLED,
                io.radiusward.server.CoaConfig.from(settings));
        cluster.awaitLeader();
        cluster.awaitServersConnected();
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
                    .contains("radiusward_server_simultaneous_use_disconnects_total{server=\"1\","
                            + "result=\"acknowledged\"} 1");
        } finally {
            coaNas.close();
        }
    }

    private int access(RadiusServer radiusServer, String user, String password, String station) throws Exception {
        TestPacket request =
                TestPacket.accessRequest(++identifier).attribute(1, user).password(password);
        if (!station.isEmpty()) {
            request.attribute(31, station);
        }
        byte[] bytes = request.messageAuthenticator().secret(SECRET).build();
        return nas.reply(radiusServer.authPort(), bytes)[0] & 0xFF;
    }

    private byte[] accounting(int status, String sessionId, String user, String station) {
        TestPacket request = TestPacket.accountingRequest(++identifier)
                .uint32(40, status)
                .attribute(44, sessionId)
                .attribute(1, user)
                .uint32(55, AccountingRequest.EVENT_TIMESTAMP + identifier);
        if (station != null) {
            request.attribute(31, station);
        }
        if (status == 2) {
            request.uint32(46, 60);
        }
        return request.secret(SECRET).build();
    }

    private void exchangeAccounting(RadiusServer radiusServer, byte[] request) throws Exception {
        assertThat(nas.reply(radiusServer.radiusPort(), request)[0] & 0xFF).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
    }
}
