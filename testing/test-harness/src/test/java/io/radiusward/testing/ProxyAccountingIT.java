/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.exporter.SinkConfig;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.testing.packets.TestPacket;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Accounting of a proxied realm (ADR 0037, milestone 5) with 3 members: committed and answered by the cluster like
 * any other, then forwarded by the {@code radius} sink to the realm's home server; a local user's stays local.
 */
@Epic("Proxying")
@Feature("Accounting of proxied realms")
@Link(name = "ADR 0037", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0037-proxying.md")
class ProxyAccountingIT {

    static final byte[] HOME_SECRET = "home-acct".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private DatagramSocket home;
    private final List<byte[]> forwarded = new CopyOnWriteArrayList<>();
    private final FakeNas nas = new FakeNas();

    @AfterEach
    void close() throws Exception {
        nas.close();
        if (home != null) {
            home.close();
        }
    }

    @Test
    void proxiedAccountingIsCommittedThenForwarded() throws Exception {
        home = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        Thread server = new Thread(this::serve, "home-accounting");
        server.setDaemon(true);
        server.start();
        try (LocalCluster cluster = LocalCluster.builder(dir.toFile())
                .members(3)
                .radiusServers(1)
                .export(id -> new ExportConfig(
                        List.of(new SinkConfig(
                                "partner",
                                "radius",
                                true,
                                0,
                                Duration.ofHours(4).toMillis(),
                                false,
                                100,
                                50,
                                2000,
                                Map.of(
                                        "mode", "sessions+events",
                                        "realms", "partner.example",
                                        "servers", "127.0.0.1:" + home.getLocalPort(),
                                        "secret", "home-acct",
                                        "timeout", "500ms"))),
                        null,
                        null))
                .start()) {
            cluster.awaitLeader();
            cluster.awaitServersConnected();
            int port = cluster.radiusServer(0).radiusPort();
            nas.ack(port, SessionIdentityIT.start(1, "s-proxied", "alice@partner.example", "aa-bb-cc-00-02-01"));
            nas.ack(port, SessionIdentityIT.start(2, "s-local", "bob", "aa-bb-cc-00-02-02"));
            LocalCluster.await(Duration.ofSeconds(30), "forwarded to the home server", () -> !forwarded.isEmpty());
            Thread.sleep(500);
            assertThat(forwarded).hasSize(1);
            String request = new String(forwarded.get(0), StandardCharsets.ISO_8859_1);
            assertThat(request)
                    .contains("s-proxied")
                    .contains("alice@partner.example")
                    .doesNotContain("s-local");
        }
    }

    /** The home server: acknowledges Accounting-Requests signed with its secret. */
    private void serve() {
        byte[] buffer = new byte[4096];
        RadiusAuthenticator a = new RadiusAuthenticator();
        while (!home.isClosed()) {
            try {
                DatagramPacket in = new DatagramPacket(buffer, buffer.length);
                home.receive(in);
                byte[] request = Arrays.copyOf(buffer, in.getLength());
                RadiusPacket p = new RadiusPacket();
                p.wrap(new UnsafeBuffer(request), 0, request.length);
                if (!a.verifyAccountingRequest(p, HOME_SECRET)) {
                    continue;
                }
                if (forwarded.stream().noneMatch(r -> Arrays.equals(r, request))) {
                    forwarded.add(request);
                }
                byte[] out = TestPacket.reply(RadiusCode.ACCOUNTING_RESPONSE, request)
                        .secret(HOME_SECRET)
                        .build();
                home.send(new DatagramPacket(out, out.length, in.getSocketAddress()));
            } catch (Exception e) {
                return;
            }
        }
    }
}
