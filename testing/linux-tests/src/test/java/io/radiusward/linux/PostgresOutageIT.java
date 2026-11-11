/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * PostgreSQL down under load ({@code -Dradiusward.outage.minutes}, default 30): accounting is acknowledged the
 * whole time (the log on disk is the buffer, far below maxLag 4h), the sink falls behind and afterwards catches
 * up; every acknowledged session ends up in the database, equal to the cluster.
 */
@Epic("Export")
@Feature("PostgreSQL outage")
@Link(
        name = "ADR 0007",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0007-sink-spi-lag-policy.md")
class PostgresOutageIT {

    @Test
    void acksContinueAndTheBacklogDrains() {
        int minutes = Integer.getInteger("radiusward.outage.minutes", 30);
        try (ContainerCluster cluster = new ContainerCluster(
                "postgres-outage", ContainerCluster.Options.defaults().postgres(true))) {
            cluster.start();
            Duration loadTime = Duration.ofMinutes(minutes).plusSeconds(60);
            CompletableFuture<LoadResult> load =
                    CompletableFuture.supplyAsync(() -> cluster.load(10, 3000, 300, loadTime, "/tmp/acks.csv"));
            ContainerCluster.sleep(20_000);
            cluster.awaitExportLagBelow("pg", 1 << 20, Duration.ofSeconds(30)); // keeping up with the load
            cluster.stopPostgres();
            long outageStarted = System.nanoTime();
            ContainerCluster.sleep(Duration.ofMinutes(minutes).toMillis() / 2);
            long lagMidway = cluster.sinks().get("pg").lagBytes();
            ContainerCluster.sleep(Duration.ofMinutes(minutes).toMillis() / 2);
            long lagAtEnd = cluster.sinks().get("pg").lagBytes();
            cluster.startPostgres();
            long drainStarted = System.nanoTime();
            System.out.printf(
                    "postgres outage of %d min: lag %d bytes midway, %d bytes at the end%n",
                    (System.nanoTime() - outageStarted) / 60_000_000_000L, lagMidway, lagAtEnd);
            LoadResult result = load.join();
            assertThat(result.failed()).as("ACKs never depended on PostgreSQL").isZero();
            assertThat(lagAtEnd)
                    .as("the sink fell behind")
                    .isGreaterThan(lagMidway)
                    .isGreaterThan(0);

            cluster.awaitExportCaughtUp("pg", Duration.ofMinutes(15));
            System.out.printf("backlog drained in %d s%n", (System.nanoTime() - drainStarted) / 1_000_000_000L);
            assertThat(cluster.verifyExport("/tmp/acks.csv").getStdout()).contains("lost=0");
            for (ContainerCluster.Member n : cluster.nodes()) {
                assertThat(ContainerCluster.metric(
                                cluster.metrics(n), "radiusward_accounting_export_lag_rejections_total"))
                        .as("no EXPORT_LAG rejections")
                        .isZero();
            }
        }
    }
}
