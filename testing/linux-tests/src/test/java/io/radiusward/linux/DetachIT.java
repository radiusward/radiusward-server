/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * An optional sink (required=false, onMaxLag detach, maxLag 20 s): PostgreSQL down never stops ACKs; the sink is
 * detached once over its limit (it no longer holds the log) and re-attaches when it has caught up, as long as the
 * log still holds its position.
 */
class DetachIT {

    @Test
    void optionalSinkDetachesAndReattaches() {
        try (ContainerCluster cluster = new ContainerCluster(
                "detach",
                ContainerCluster.Options.defaults()
                        .postgres(true)
                        .env("RADIUSWARD_SINK_PG_REQUIRED", "false")
                        .env("RADIUSWARD_SINK_PG_ON_MAX_LAG", "detach")
                        .env("RADIUSWARD_SINK_PG_MAX_LAG", "20s"))) {
            cluster.start();
            cluster.stopPostgres();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 1000, 200, Duration.ofSeconds(60), "/tmp/acks.csv"));
            ContainerCluster.sleep(45_000);
            ContainerCluster.SinkRow detached = cluster.sinks().get("pg");
            System.out.println("while PostgreSQL is down: " + detached);
            assertThat(detached.detached()).as("detached over maxLag").isTrue();
            assertThat(detached.epoch())
                    .as("the lease stays put while the database is down")
                    .isEqualTo(1);
            LoadResult result = load.join();
            assertThat(result.failed()).as("an optional sink never blocks ACKs").isZero();

            cluster.startPostgres();
            cluster.awaitExportCaughtUp("pg", Duration.ofMinutes(3));
            assertThat(cluster.sinks().get("pg").detached())
                    .as("re-attached after catching up")
                    .isFalse();
            assertThat(cluster.verifyExport("/tmp/acks.csv").getStdout()).contains("lost=0");
        }
    }
}
