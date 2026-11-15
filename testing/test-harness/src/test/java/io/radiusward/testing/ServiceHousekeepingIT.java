/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.common.Profile;
import io.radiusward.gateway.NasClient;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.tools.admin.AdminClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the cluster service does besides applying commands: the housekeeping timer ({@code service.sweep.interval})
 * removes idle sessions and expired tombstones on every member alike, and the service counts gateways that disagree
 * on a NAS entry's device identity.
 */
@Epic("Accounting")
@Feature("Cluster service housekeeping")
class ServiceHousekeepingIT {

    @TempDir
    Path dir;

    private final FakeNas nas = new FakeNas();
    private LocalCluster cluster;

    @AfterEach
    void close() throws Exception {
        nas.close();
        if (cluster != null) {
            cluster.close();
        }
    }

    @Test
    void theSweepTimerRemovesIdleSessionsAndExpiredTombstonesOnEveryMember() throws Exception {
        // tombstones kept 1 s, sessions idle after 2 s, swept every 300 ms (in production: 1 h, 2 h, 60 s)
        AccountingStateMachine.Settings settings = AccountingStateMachine.Settings.defaults(Profile.SMALL.maxSessions())
                .withTombstoneMs(1_000L)
                .withIdleTimeoutMs(2_000L)
                .withExactKeyWindowMs(1_000L);
        cluster = LocalCluster.builder(dir.toFile())
                .members(3)
                .gateways(1)
                .settings(settings)
                .sweepInterval(Duration.ofMillis(300))
                .start();
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        int port = cluster.gateway(0).radiusPort();
        long now = System.currentTimeMillis() / 1000;
        nas.ack(port, AccountingRequest.request(1, 1, "idle", 0, now)); // started, then never heard of again
        nas.ack(port, AccountingRequest.request(2, 1, "done", 0, now));
        nas.ack(port, AccountingRequest.request(3, 2, "done", 30, now)); // stopped: a tombstone
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "the idle session and the tombstone are swept",
                    () -> admin.state().active() == 0 && admin.state().stopped() == 0);
            assertThat(admin.state().applied()).isEqualTo(3);
        }
        cluster.awaitConverged();
        long digest = cluster.awaitLeader().stats().digest();
        for (int i = 0; i < 3; i++) {
            ClusterNode member = cluster.node(i);
            assertThat(member.stats().activeSessions()).as("member %d", i).isZero();
            assertThat(member.stats().digest())
                    .as("member %d swept at the same log position", i)
                    .isEqualTo(digest);
        }

        // the timer keeps running: a session that goes idle later is swept too
        nas.ack(port, AccountingRequest.request(4, 1, "later", 0, System.currentTimeMillis() / 1000));
        try (AdminClient admin = cluster.admin()) {
            LocalCluster.await(
                    Duration.ofSeconds(30),
                    "the later session is swept",
                    () -> admin.state().active() == 0);
        }
    }

    @Test
    void gatewaysThatDisagreeOnTheDeviceIdentityOfANasEntryAreCounted() throws Exception {
        cluster = LocalCluster.start(dir.toFile(), 3, 0);
        cluster.startGateway(1, 0, LocalCluster.registry(NasClient.Identity.NAS_IDENTIFIER));
        cluster.startGateway(2, 0, LocalCluster.registry(NasClient.Identity.NAS_IP_ADDRESS));
        cluster.awaitLeader();
        cluster.awaitGatewaysConnected();
        nas.ack(cluster.gateway(0).radiusPort(), start(1, "s-1"));
        assertThat(cluster.awaitLeader().stats().identityMismatches()).isZero();

        nas.ack(cluster.gateway(1).radiusPort(), start(2, "s-2"));
        nas.ack(cluster.gateway(1).radiusPort(), start(3, "s-3"));
        ClusterNode leader = cluster.awaitLeader();
        LocalCluster.await(
                Duration.ofSeconds(10),
                "the leader counted the second gateway's commands",
                () -> leader.stats().identityMismatches() == 2);
        assertThat(leader.metrics()).containsPattern("radiusward_nas_identity_mismatches_total\\{member=\"\\d\"\\} 2");
        assertThat(leader.stateJson()).contains("\"identityMismatches\":2");
    }

    /** An Accounting-Request Start from an access point that names itself both ways. */
    private static byte[] start(int id, String sessionId) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id)
                .uint32(40, 1)
                .attribute(44, sessionId)
                .attribute(32, "ap-1")
                .uint32(4, 0x7F000001)
                .uint32(55, System.currentTimeMillis() / 1000);
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, FakeNas.SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }
}
