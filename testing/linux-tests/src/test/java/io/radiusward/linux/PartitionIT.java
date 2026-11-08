/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * The leader loses its links to both followers (iptables) while the gateways still reach it. The majority
 * elects a new leader and the gateways move there; the old leader cannot commit, so whatever it might
 * acknowledge would show up as lost. After healing it rejoins as a follower with the same state.
 */
class PartitionIT {

    @Test
    void isolatedLeaderNeverAcknowledgesAndRejoins() {
        try (ContainerCluster cluster = new ContainerCluster("partition", ContainerCluster.Options.defaults())) {
            cluster.start();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 5000, 1000, Duration.ofSeconds(30), "/tmp/acks.csv"));
            ContainerCluster.sleep(8_000);
            ContainerCluster.Member old = cluster.awaitLeader(Duration.ofSeconds(5));
            List<String> followers = cluster.nodes().stream()
                    .filter(n -> n != old)
                    .map(ContainerCluster.Member::ip)
                    .toList();
            cluster.isolate(old, followers);

            ContainerCluster.Member next = cluster.awaitLeaderOtherThan(old, Duration.ofSeconds(15));
            System.out.println("partition: " + old.name() + " isolated, new leader " + next.name());
            ContainerCluster.sleep(8_000);
            cluster.heal(old);
            LoadResult result = load.join();

            assertThat(result.acked()).isPositive();
            cluster.awaitConverged(Duration.ofSeconds(60));
            Map<String, String> oldState = cluster.state(old);
            assertThat(oldState).isNotNull();
            assertThat(oldState.get("role")).as("old leader after healing").isEqualTo("FOLLOWER");
            assertThat(cluster.verifyAcks("/tmp/acks.csv").getExitCode())
                    .as("no acknowledged event lost")
                    .isZero();
        }
    }
}
