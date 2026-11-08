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
 * {@code kill -9} of the leader container at ~2k requests/s: the cluster is writable again well within the
 * 3 s client timeout, so no NAS has to retransmit (ADR 0011: gateways resubmit pending commands to the new
 * leader).
 */
class FailoverTimingIT {

    @Test
    void leaderKillUnderLoadNeedsNoRetransmission() {
        try (ContainerCluster cluster = new ContainerCluster("failover-timing", ContainerCluster.Options.defaults())) {
            cluster.start();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 10_000, 2000, Duration.ofSeconds(25), "/tmp/acks.csv"));
            ContainerCluster.sleep(10_000);
            ContainerCluster.Member leader = cluster.awaitLeader(Duration.ofSeconds(5));
            long killedAt = System.nanoTime();
            cluster.kill(leader);
            ContainerCluster.Member next = cluster.awaitLeader(Duration.ofSeconds(10));
            System.out.printf(
                    "failover: killed %s, new leader %s reported after %d ms (includes probe latency)%n",
                    leader.name(), next.name(), (System.nanoTime() - killedAt) / 1_000_000);
            LoadResult result = load.join();

            assertThat(result.failed()).as("unacknowledged events").isZero();
            assertThat(result.retransmissions())
                    .as("requests needing a second attempt")
                    .isZero();
            assertThat(result.maxMs()).as("worst ACK latency, ms").isLessThan(3000);

            cluster.restart(leader);
            cluster.awaitReady(cluster.nodes(), Duration.ofSeconds(60));
            cluster.awaitConverged(Duration.ofSeconds(60));
            assertThat(cluster.verifyAcks("/tmp/acks.csv").getExitCode()).isZero();
        }
    }
}
