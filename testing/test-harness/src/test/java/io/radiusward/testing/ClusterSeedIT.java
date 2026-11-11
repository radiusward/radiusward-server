/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.cluster.node.ClusterNodeConfig;
import io.radiusward.cluster.node.ClusterSeed;
import io.radiusward.cluster.node.LogPurgeConfig;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A member that lost its volume after the log was purged is seeded from the others and catches up (ADR 0063); without
 * seeding it could not (the Kubernetes spike, ADR 0062).
 */
@Epic("Cluster")
@Feature("Seeding a replaced member")
@Link(
        name = "ADR 0063",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0063-seeding-a-replaced-member.md")
class ClusterSeedIT {

    @TempDir
    Path dir;

    @Test
    void aMemberWithALostVolumeIsSeededAndCatchesUp() throws Exception {
        try (LocalCluster cluster = LocalCluster.start(
                dir.toFile(),
                3,
                2,
                LocalCluster.freePortBase(3),
                new int[2],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                new LogPurgeConfig(true, false, 4 << 20, Duration.ofSeconds(1)))) {
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();
            LogPurgeIT.load(cluster, 0);
            LogPurgeIT.snapshot(cluster, 1);
            LogPurgeIT.load(cluster, 100_000);
            LogPurgeIT.snapshot(cluster, 2);
            LogPurgeIT.load(cluster, 200_000);
            LocalCluster.await(Duration.ofSeconds(60), "every member purged", () -> {
                for (int i = 0; i < 3; i++) {
                    if (LogPurgeIT.logStart(cluster.node(i)) <= 0) {
                        return false;
                    }
                }
                return true;
            });

            // a new leadership term after the snapshots: the seeded log must span the terms in between
            int oldLeader = cluster.awaitLeader().config().nodeId();
            cluster.stopNode(oldLeader);
            cluster.awaitLeader();
            LogPurgeIT.load(cluster, 250_000);
            cluster.startNode(oldLeader);
            cluster.awaitConverged();

            int lost = (cluster.awaitLeader().config().nodeId() + 1) % 3;
            cluster.stopNode(lost);
            ClusterNodeConfig config = cluster.nodeConfig(lost);
            delete(config.dataDir());
            assertThat(ClusterSeed.empty(config)).isTrue();
            LogPurgeIT.load(cluster, 300_000); // the cluster goes on while the member is replaced

            assertThat(ClusterSeed.seedIfEmpty(config, Duration.ofSeconds(20)))
                    .as("seeded from the others")
                    .isTrue();
            assertThat(ClusterSeed.empty(config)).isFalse();
            cluster.startNode(lost);
            LogPurgeIT.load(cluster, 400_000);
            cluster.awaitConverged();
            assertThat(cluster.node(lost).stats().applied())
                    .isEqualTo(cluster.awaitLeader().stats().applied());
            try {
                LocalCluster.await(
                        Duration.ofSeconds(20),
                        "seeded member ready",
                        () -> cluster.node(lost).ready().up());
            } finally {
                System.out.println(
                        "seeded member readiness: " + cluster.node(lost).ready().detail());
            }
        }
    }

    @Test
    void withoutASnapshotTheMemberCatchesUpFromTheLog() throws Exception {
        try (LocalCluster cluster = LocalCluster.start(
                dir.toFile(),
                3,
                2,
                LocalCluster.freePortBase(3),
                new int[2],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                LogPurgeConfig.DEFAULTS)) {
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();
            LogPurgeIT.load(cluster, 0);
            int lost = (cluster.awaitLeader().config().nodeId() + 1) % 3;
            cluster.stopNode(lost);
            ClusterNodeConfig config = cluster.nodeConfig(lost);
            delete(config.dataDir());
            assertThat(ClusterSeed.seedIfEmpty(config, Duration.ofSeconds(20)))
                    .as("nothing to seed from: no snapshot")
                    .isFalse();
            assertThat(ClusterSeed.empty(config)).isTrue();
            cluster.startNode(lost);
            cluster.awaitConverged();
            assertThat(cluster.node(lost).stats().applied())
                    .isEqualTo(cluster.awaitLeader().stats().applied());
        }
    }

    @Test
    void withoutAClusterTheMemberStartsEmpty() throws Exception {
        try (LocalCluster cluster = LocalCluster.start(
                dir.toFile(),
                3,
                0,
                LocalCluster.freePortBase(3),
                new int[0],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                LogPurgeConfig.DEFAULTS)) {
            ClusterNodeConfig config = cluster.nodeConfig(0);
            for (int i = 0; i < 3; i++) {
                cluster.stopNode(i);
            }
            delete(config.dataDir());
            long start = System.nanoTime();
            assertThat(ClusterSeed.seedIfEmpty(config, Duration.ofSeconds(3))).isFalse();
            assertThat(System.nanoTime() - start)
                    .isLessThan(Duration.ofSeconds(15).toNanos());
            assertThat(ClusterSeed.empty(config))
                    .as("nothing half-copied left behind")
                    .isTrue();
        }
    }

    private static void delete(File file) throws IOException {
        if (!file.exists()) {
            return;
        }
        try (Stream<Path> files = Files.walk(file.toPath())) {
            files.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }
}
