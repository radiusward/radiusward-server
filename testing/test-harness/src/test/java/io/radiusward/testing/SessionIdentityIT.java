/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.gateway.UserKeys;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Session identification in the replicated state (state version 7, ADR 0036): with 3 members and a gateway, an
 * accounting Start with a user names its session in the admin reports — by key, by user, by page — and survives a
 * member that restarts from a snapshot.
 */
@Epic("Accounting")
@Feature("Session identity")
@Link(
        name = "ADR 0036",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0036-coa-and-session-identity.md")
class SessionIdentityIT {

    static final byte[] SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path dir;

    private LocalCluster cluster;
    private final LocalClusterIT nas = new LocalClusterIT();

    @AfterEach
    void close() throws Exception {
        nas.close();
        if (cluster != null) {
            cluster.close();
        }
    }

    @Test
    void sessionsAreNamedInTheAdminReports() throws Exception {
        // members report their supported version with the log purger's position reports (ADR 0005)
        cluster = LocalCluster.start(
                dir.resolve("cluster").toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new io.radiusward.cluster.node.LogPurgeConfig(true, false, 128 << 20, Duration.ofSeconds(1)));
        cluster.startGateway(1, LocalCluster.freePort());
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        nas.exchange(cluster.gateway(0).radiusPort(), start(9, "warm-up", "nobody", "aa-bb-cc-00-00-09"));
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(20),
                    "state version 7 active",
                    () -> admin.state().activeVersion() >= 7);
            int port = cluster.gateway(0).radiusPort();
            nas.exchange(port, start(1, "id-1", "Alice", "aa-bb-cc-00-00-01")); // the warm-up came before 7
            nas.exchange(port, start(2, "id-2", "alice", "aa-bb-cc-00-00-02"));
            nas.exchange(port, start(3, "id-3", "bob", "aa-bb-cc-00-00-03"));

            long[] key = LocalClusterIT.sessionKey("id-1");
            AdminClient.Session one = admin.session(key[0], key[1]);
            assertThat(one.attribute(44)).isEqualTo("id-1");
            assertThat(one.attribute(1)).isEqualTo("Alice");
            assertThat(one.attribute(8)).as("Framed-IP-Address is binary").isNotNull();
            assertThat(one.attribute(31)).isEqualTo("aa-bb-cc-00-00-01");

            byte[] alice = "alice".getBytes(StandardCharsets.US_ASCII);
            List<AdminClient.ListedSession> sessions = admin.userSessions(UserKeys.user(new UnsafeBuffer(alice), 0, 5));
            assertThat(sessions)
                    .as("User-Name case folded: both of alice's")
                    .extracting(s -> s.attribute(44))
                    .containsExactlyInAnyOrder("id-1", "id-2");
            assertThat(sessions).allSatisfy(s -> assertThat(s.firstSeen()).isPositive());

            AdminClient.SessionPage first = admin.sessionPage(0, 2);
            assertThat(first.sessions()).hasSize(2);
            AdminClient.SessionPage rest = admin.sessionPage(first.nextSlot(), 2);
            assertThat(rest.nextSlot()).isEqualTo(-1);
            assertThat(rest.sessions())
                    .as("the warm-up session has no user: applied before 6")
                    .hasSize(1);

            io.radiusward.cluster.node.ClusterNode leader = cluster.awaitLeader();
            assertThat(leader.requestSnapshot()).isTrue(); // the restarted member loads it, then replays the rest
            Thread.sleep(500);
            int restarted = leader.config().nodeId() == 0 ? 1 : 0;
            cluster.stopNode(restarted);
            cluster.startNode(restarted);
            cluster.awaitConverged();
            assertThat(admin.session(key[0], key[1]).attribute(1)).isEqualTo("Alice");
        }
    }

    static byte[] start(int id, String sessionId, String user, String mac) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id)
                .uint32(40, 1)
                .attribute(44, sessionId)
                .attribute(1, user)
                .attribute(31, mac)
                .attribute(8, new byte[] {10, 9, 0, (byte) id})
                .uint32(55, 1_780_000_000L);
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }
}
