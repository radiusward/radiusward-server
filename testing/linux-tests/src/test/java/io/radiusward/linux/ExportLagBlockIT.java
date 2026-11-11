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
 * A required sink with maxLag 30 s and onMaxLag block: while PostgreSQL is down the cluster stops acknowledging
 * new accounting once the sink is 30 s behind ({@code EXPORT_LAG}), and acknowledges again as soon as the sink has
 * caught up. Nothing acknowledged is missing in the database.
 */
@Epic("Export")
@Feature("Required sink stops acknowledgements")
@Link(
        name = "ADR 0007",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0007-sink-spi-lag-policy.md")
class ExportLagBlockIT {

    @Test
    void requiredSinkOverItsLimitStopsAcks() {
        try (ContainerCluster cluster = new ContainerCluster(
                "export-lag-block",
                ContainerCluster.Options.defaults().postgres(true).env("RADIUSWARD_SINK_PG_MAX_LAG", "30s"))) {
            cluster.start();
            assertThat(cluster.load(10, 1000, 200, Duration.ofSeconds(10), "/tmp/before.csv", 0)
                            .failed())
                    .isZero();
            cluster.awaitExportCaughtUp("pg", Duration.ofSeconds(60));

            cluster.stopPostgres();
            CompletableFuture<LoadResult> during = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 1000, 200, Duration.ofSeconds(90), "/tmp/during.csv", 10_000));
            ContainerCluster.sleep(70_000);
            double rejections = 0;
            for (ContainerCluster.Member n : cluster.nodes()) {
                rejections += ContainerCluster.metric(
                        cluster.metrics(n), "radiusward_accounting_export_lag_rejections_total");
            }
            cluster.startPostgres();
            LoadResult blocked = during.join();
            System.out.printf("blocked phase: %s, EXPORT_LAG rejections %.0f%n", blocked, rejections);
            assertThat(rejections)
                    .as("EXPORT_LAG rejections while the sink was over maxLag")
                    .isPositive();
            assertThat(blocked.failed()).as("requests unanswered while blocked").isPositive();

            cluster.awaitExportCaughtUp("pg", Duration.ofMinutes(5));
            LoadResult after = cluster.load(10, 1000, 200, Duration.ofSeconds(15), "/tmp/after.csv", 20_000);
            assertThat(after.failed()).as("ACKs again after catching up").isZero();
            cluster.awaitExportCaughtUp("pg", Duration.ofMinutes(2));
            for (String log : new String[] {"/tmp/before.csv", "/tmp/during.csv", "/tmp/after.csv"}) {
                assertThat(cluster.verifyExport(log).getStdout()).as(log).contains("lost=0");
            }
        }
    }
}
