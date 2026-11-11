/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aeron.cluster.ClusterBackup;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.cluster.node.ClusterBackupNode;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.node.ClusterNodeConfig;
import io.radiusward.cluster.node.ClusterRestore;
import io.radiusward.cluster.node.ClusterSeed;
import io.radiusward.cluster.node.LogPurgeConfig;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.stream.Stream;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * A backup outside the cluster (ADR 0065) keeps the latest snapshot and the live log; after every member lost its data
 * — a lost quorum — all three are restored from it and the cluster goes on with every acknowledged event.
 */
@Epic("Cluster")
@Feature("Backup and restore")
@Link(
        name = "ADR 0065",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0065-cluster-backup.md")
class ClusterBackupIT {

    @TempDir
    Path dir;

    /**
     * @param automatic whether the members restore themselves when they find no cluster ({@code cluster.restore.from},
     *     as on ECS), or the operator runs {@code cluster-restore} for each
     */
    @ParameterizedTest(name = "automatic restore: {0}")
    @ValueSource(booleans = {false, true})
    void aClusterThatLostEveryMemberIsRestoredFromTheBackup(boolean automatic) throws Exception {
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
            ClusterNodeConfig member = cluster.nodeConfig(0);
            ClusterBackupNode.Settings settings = new ClusterBackupNode.Settings(
                    member.members(),
                    member.basePort(),
                    "localhost",
                    LocalCluster.freePortBase(1),
                    dir.resolve("backup").toFile(),
                    dir.resolve("backup-aeron").toString(),
                    ClusterBackup.SourceType.FOLLOWER,
                    Duration.ofSeconds(2),
                    member.fileSyncLevel(),
                    member.purge().segmentLength());

            try (ClusterBackupNode backup = ClusterBackupNode.launch(settings)) {
                LogPurgeIT.load(cluster, 0);
                LogPurgeIT.snapshot(cluster, 1);
                LogPurgeIT.load(cluster, 100_000);
                LogPurgeIT.snapshot(cluster, 2);
                LogPurgeIT.load(cluster, 200_000); // after the last snapshot: only the live log has these
                cluster.awaitConverged();
                ClusterNode leader = cluster.awaitLeader();
                long position = leader.stats().lastPosition();
                LocalCluster.await(
                        Duration.ofSeconds(60),
                        "backup ready and caught up",
                        () -> backup.ready().up()
                                && backup.liveLogPosition() >= position
                                && backup.latestSnapshot() != null
                                && backup.latestSnapshot().logPosition > 0);
                assertThat(backup.health().up()).isTrue();
                assertThat(backup.ready().detail()).startsWith("backing up, snapshot at ");
                assertThat(backup.stateJson())
                        .contains("\"component\":\"cluster-backup\"")
                        .contains("\"state\":\"BACKING_UP\"");
                assertThat(backup.dataDir()).isEqualTo(settings.dataDir());
                io.radiusward.common.management.PrometheusWriter.validate(backup.metrics());
                assertThat(backup.metrics())
                        .contains("radiusward_backup_snapshot_timestamp_seconds ")
                        .contains("radiusward_backup_state{state=\"backing_up\"} 1")
                        .contains("radiusward_backup_live_log_position_bytes ");
                long applied = leader.stats().applied();

                long[] connects = cluster.gateways().stream()
                        .mapToLong(g -> g.stats().get(io.radiusward.gateway.GatewayStats.Counter.CLUSTER_CONNECTS))
                        .toArray();
                // every member loses its data: no quorum, nothing to seed from
                for (int i = 0; i < 3; i++) {
                    cluster.stopNode(i);
                    delete(cluster.nodeConfig(i).dataDir());
                }
                backup.close();
                // a backup that went through a Mac carries AppleDouble files a member cannot read
                Files.writeString(settings.dataDir().toPath().resolve("archive/._1"), "resource fork");
                // backups are often mounted read-only; Aeron opens a recording log for writing
                assertThat(settings.dataDir()
                                .toPath()
                                .resolve("cluster/recording.log")
                                .toFile()
                                .setWritable(false))
                        .isTrue();

                assertThatThrownBy(() -> ClusterRestore.restore(dir.resolve("nothing"), cluster.nodeConfig(0)))
                        .as("a directory without a snapshot is no backup")
                        .isInstanceOf(IllegalStateException.class);
                if (automatic) {
                    assertThat(ClusterSeed.prepare(
                                    cluster.nodeConfig(0), Duration.ofSeconds(2), dir.resolve("nothing")))
                            .as("no cluster and no backup: a new cluster")
                            .isEqualTo(ClusterSeed.Outcome.STARTS_EMPTY);
                    assertThat(ClusterSeed.empty(cluster.nodeConfig(0))).isTrue();
                    for (int i = 0; i < 3; i++) {
                        assertThat(ClusterSeed.prepare(
                                        cluster.nodeConfig(i),
                                        Duration.ofSeconds(2),
                                        settings.dataDir().toPath()))
                                .as("member %d finds no cluster and restores itself", i)
                                .isEqualTo(ClusterSeed.Outcome.RESTORED);
                    }
                    assertThat(ClusterSeed.prepare(cluster.nodeConfig(0), Duration.ofSeconds(2), null))
                            .isEqualTo(ClusterSeed.Outcome.NOT_EMPTY);
                } else {
                    for (int i = 0; i < 3; i++) {
                        assertThat(ClusterRestore.restore(settings.dataDir().toPath(), cluster.nodeConfig(i)))
                                .isPositive();
                    }
                }
                assertThatThrownBy(
                                () -> ClusterRestore.restore(settings.dataDir().toPath(), cluster.nodeConfig(0)))
                        .as("never over a member's data")
                        .isInstanceOf(IllegalStateException.class);
                for (int i = 0; i < 3; i++) {
                    cluster.startNode(i);
                }
                cluster.awaitLeader();
                cluster.awaitConverged();
                for (int i = 0; i < 3; i++) {
                    assertThat(cluster.node(i).stats().applied())
                            .as("member %d has every acknowledged event", i)
                            .isEqualTo(applied);
                }
                // the gateways' sessions belonged to the cluster before the loss: they reconnect first
                LocalCluster.await(Duration.ofSeconds(60), "gateways reconnected", () -> {
                    for (int g = 0; g < connects.length; g++) {
                        if (cluster.gateways()
                                        .get(g)
                                        .stats()
                                        .get(io.radiusward.gateway.GatewayStats.Counter.CLUSTER_CONNECTS)
                                <= connects[g]) {
                            return false;
                        }
                    }
                    return true;
                });
                cluster.awaitGatewaysConnected();
                LogPurgeIT.load(cluster, 300_000); // and accepts new ones
                cluster.awaitConverged();
            }
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
