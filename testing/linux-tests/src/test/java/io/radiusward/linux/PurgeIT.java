/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * Steady load for {@code -Dradiusward.purge.minutes} (default 60) with snapshots every minute, 4 MiB segments
 * and PostgreSQL attached: the archive on every member stays bounded while far more log than that is written,
 * and nothing acknowledged is missing in the database.
 */
class PurgeIT {

    @Test
    void diskStaysBoundedUnderSteadyLoad() {
        int minutes = Integer.getInteger("radiusward.purge.minutes", 60);
        try (ContainerCluster cluster = new ContainerCluster(
                "purge",
                ContainerCluster.Options.defaults()
                        .postgres(true)
                        .env("RADIUSWARD_SNAPSHOT_INTERVAL", "1m")
                        .env("RADIUSWARD_ARCHIVE_SEGMENT_LENGTH", "4m")
                        .env("RADIUSWARD_LOG_PURGE_INTERVAL", "10s"))) {
            cluster.start();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 3000, 600, Duration.ofMinutes(minutes), "/tmp/acks.csv"));
            List<Long> sizes = new ArrayList<>();
            for (int m = 1; m <= minutes; m++) {
                ContainerCluster.sleep(60_000);
                long max = 0;
                for (ContainerCluster.Member n : cluster.nodes()) {
                    String du = cluster.shell(n, "du -sb /var/lib/radiusward/node-*/archive | cut -f1")
                            .getStdout()
                            .trim();
                    max = Math.max(max, Long.parseLong(du));
                }
                sizes.add(max);
                System.out.printf("minute %d: largest archive %d MiB%n", m, max >> 20);
            }
            LoadResult result = load.join();
            assertThat(result.failed()).isZero();
            long written = Long.parseLong(String.valueOf((long) ContainerCluster.metric(
                    cluster.metrics(cluster.nodes().get(0)), "radiusward_cluster_log_position_bytes")));
            long late = sizes.subList(sizes.size() / 2, sizes.size()).stream()
                    .mapToLong(Long::longValue)
                    .max()
                    .orElse(0);
            long early = sizes.subList(0, sizes.size() / 2).stream()
                    .mapToLong(Long::longValue)
                    .max()
                    .orElse(0);
            System.out.printf(
                    "log written %d MiB, largest archive %d MiB in the first half, %d MiB in the second%n",
                    written >> 20, early >> 20, late >> 20);
            assertThat(written).as("more log written than kept: purged").isGreaterThan(2 * late);
            assertThat(late)
                    .as("does not grow with the log: at most two segments more")
                    .isLessThanOrEqualTo(early + (8L << 20));
            assertThat(late).as("bounded: a few snapshot intervals").isLessThan(64L << 20);
            for (ContainerCluster.Member n : cluster.nodes()) {
                assertThat(ContainerCluster.metric(cluster.metrics(n), "radiusward_log_start_bytes"))
                        .as(n.name() + " purged")
                        .isPositive();
            }
            cluster.awaitExportCaughtUp("pg", Duration.ofMinutes(2));
            assertThat(cluster.verifyExport("/tmp/acks.csv").getStdout()).contains("lost=0");
        }
    }
}
