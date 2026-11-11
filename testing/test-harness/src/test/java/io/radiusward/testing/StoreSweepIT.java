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
import io.radiusward.gateway.CoaConfig;
import io.radiusward.gateway.Gateway;
import io.radiusward.gateway.RadsecConfig;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.tools.admin.AdminClient;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The store sweep (ADR 0036) with 3 members: users online are looked up again; one rejected since is disconnected,
 * one whose reply items changed gets a CoA with them, one no store has any more is left alone.
 */
@Epic("Authentication")
@Feature("Store sweep")
@Link(
        name = "ADR 0036",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0036-coa-and-session-identity.md")
class StoreSweepIT {

    static final byte[] SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private LocalCluster cluster;
    private DatagramChannel fakeNas;
    private final List<byte[]> requests = new CopyOnWriteArrayList<>();
    private final LocalClusterIT nas = new LocalClusterIT();

    @AfterEach
    void close() throws Exception {
        nas.close();
        if (fakeNas != null) {
            fakeNas.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }

    @Test
    void disabledUsersAreDisconnectedChangedOnesGetACoa() throws Exception {
        Path users = dir.resolve("users");
        Files.writeString(users, """
                alice   Cleartext-Password := "a"
                        Session-Timeout = 3600
                bob     Cleartext-Password := "b"
                carol   Cleartext-Password := "c"
                """);
        fakeNas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        CompletableFuture.runAsync(this::answer);
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        Config settings = Config.of(Map.ofEntries(
                Map.entry("auth.stores", "local"),
                Map.entry("auth.store.local.type", "file"),
                Map.entry("auth.store.local.path", users.toString()),
                Map.entry("auth.store.local.reload.interval", "100ms"),
                Map.entry("auth.cache.ttl", "0s"),
                Map.entry("auth.plugins.dir", dir.resolve("plugins").toString()),
                Map.entry("coa.enabled", "true"),
                Map.entry("coa.timeout", "500ms"),
                Map.entry("coa.sweep.enabled", "true"),
                Map.entry("coa.sweep.interval", "1s"),
                Map.entry("coa.sweep.rate", "100"),
                Map.entry(
                        "nas." + LocalCluster.NAS_NAME + ".coa.port",
                        Integer.toString(((InetSocketAddress) fakeNas.getLocalAddress()).getPort()))));
        AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
        Gateway gateway = cluster.startGateway(
                1,
                0,
                LocalCluster.registry(),
                auth,
                Gateway.storeHandler(settings, auth),
                RadsecConfig.DISABLED,
                CoaConfig.from(settings));
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        int port = gateway.radiusPort();
        nas.exchange(port, SessionIdentityIT.start(9, "warm-up", "nobody", "aa-bb-cc-00-00-09"));
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "state version 7",
                    () -> admin.state().activeVersion() >= 7);
        }
        nas.exchange(port, SessionIdentityIT.start(1, "s-alice", "alice", "aa-bb-cc-00-00-01"));
        nas.exchange(port, SessionIdentityIT.start(2, "s-bob", "bob", "aa-bb-cc-00-00-02"));
        nas.exchange(port, SessionIdentityIT.start(3, "s-carol", "carol", "aa-bb-cc-00-00-03"));
        long before = sweeps(gateway); // sweeps run from the start: one now may have begun before the sessions
        LocalCluster.await(Duration.ofSeconds(10), "a whole sweep that saw them", () -> sweeps(gateway) >= before + 2);
        assertThat(requests).as("nothing changed yet").isEmpty();

        Files.writeString(users, """
                alice   Cleartext-Password := "a"
                        Session-Timeout = 600
                bob     Cleartext-Password := "b", Auth-Type := Reject
                """);
        LocalCluster.await(
                Duration.ofSeconds(15),
                "bob disconnected and alice changed",
                () -> requests.stream().anyMatch(r -> r[0] == 40)
                        && requests.stream().anyMatch(r -> r[0] == 43));
        long done = sweeps(gateway);
        LocalCluster.await(Duration.ofSeconds(10), "another sweep", () -> sweeps(gateway) > done + 1);

        // bob's session stays active (this NAS sends no Stop), so every sweep asks again; carol is in no store any
        // more, but kept (coa.sweep.missing = keep)
        assertThat(requests).allSatisfy(r -> assertThat(CoaIT.attribute(r, 1)).isIn("alice", "bob"));
        assertThat(requests.stream().filter(r -> r[0] == 40))
                .isNotEmpty()
                .allSatisfy(r -> assertThat(CoaIT.attribute(r, 1)).isEqualTo("bob"));
        List<byte[]> coas = requests.stream().filter(r -> r[0] == 43).toList();
        assertThat(coas).as("one CoA: the change, sent once").hasSize(1);
        byte[] coa = coas.get(0);
        assertThat(CoaIT.attribute(coa, 1)).isEqualTo("alice");
        int at = attributeAt(coa, 27);
        assertThat(new UnsafeBuffer(coa).getInt(at + 2, java.nio.ByteOrder.BIG_ENDIAN))
                .as("the new Session-Timeout")
                .isEqualTo(600);
        assertThat(gateway.metrics())
                .contains("radiusward_gateway_store_sweep_total{gateway=\"1\",result=\"changed\"} 1");
    }

    private static long sweeps(Gateway gateway) {
        String metrics = gateway.metrics();
        String key = "radiusward_gateway_store_sweep_total{gateway=\"1\",result=\"sweeps\"} ";
        int at = metrics.indexOf(key);
        return at < 0
                ? 0
                : Long.parseLong(metrics.substring(at + key.length(), metrics.indexOf('\n', at))
                        .trim());
    }

    private static int attributeAt(byte[] packet, int type) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(packet), 0, packet.length);
        return p.findAttribute(type);
    }

    /** The fake NAS: acknowledges every request whose authenticator verifies. */
    private void answer() {
        ByteBuffer in = ByteBuffer.allocate(4096);
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        while (true) {
            try {
                in.clear();
                InetSocketAddress from = (InetSocketAddress) fakeNas.receive(in);
                byte[] request = Arrays.copyOf(in.array(), in.position());
                RadiusPacket p = new RadiusPacket();
                p.wrap(new UnsafeBuffer(request), 0, request.length);
                if (authenticator.verifyAccountingRequest(p, SECRET)) {
                    requests.add(request);
                    fakeNas.send(ByteBuffer.wrap(CoaIT.ack(request, SECRET)), from);
                }
            } catch (Exception e) {
                return; // closed
            }
        }
    }
}
