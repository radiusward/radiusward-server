/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;

/**
 * All three members lose power at once under load. The data directory lives on LazyFS, so whatever was not
 * fsynced is gone after the restart. With {@code archive.file.sync.level=2} the cluster must come back and hold
 * every acknowledged event. The control run with level 0 must lose acknowledged events (or not come back at
 * all: its catalog is zeroed), otherwise the setup does not simulate a power loss and the first test proves
 * nothing.
 */
class PowerLossIT {

    /** {@code verify == null}: the cluster did not recover. */
    private record Outcome(LoadResult load, ExecResult verify) {}

    @Test
    void fsyncedClusterKeepsEveryAcknowledgedEvent() {
        Outcome outcome = run("power-loss-fsync-2", 2);
        assertThat(outcome.verify())
                .as("cluster recovered after the power loss")
                .isNotNull();
        assertThat(outcome.verify().getStdout()).contains("lost=0");
        assertThat(outcome.verify().getExitCode()).isZero();
    }

    @Test
    void controlRunWithoutFsyncLosesAcknowledgedEvents() {
        Outcome outcome = run("power-loss-fsync-0", 0);
        if (outcome.verify() != null) {
            assertThat(outcome.verify().getExitCode())
                    .as("acknowledged events lost without fsync")
                    .isNotZero();
            assertThat(outcome.verify().getStdout()).doesNotContain("lost=0");
        }
    }

    private static Outcome run(String name, int fileSyncLevel) {
        try (ContainerCluster cluster = new ContainerCluster(
                name,
                ContainerCluster.Options.defaults().fileSyncLevel(fileSyncLevel).lazyFs(true))) {
            cluster.start();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 2500, 500, Duration.ofSeconds(20), "/tmp/acks.csv"));
            ContainerCluster.sleep(10_000);
            cluster.powerLoss();
            LoadResult result = load.join();
            assertThat(result.acked()).as("acknowledged events").isPositive();
            try {
                cluster.awaitReady(cluster.nodes(), Duration.ofSeconds(60));
                cluster.awaitLeader(Duration.ofSeconds(30));
            } catch (IllegalStateException e) {
                System.out.println(name + ": cluster did not recover: " + e.getMessage());
                return new Outcome(result, null);
            }
            return new Outcome(result, cluster.verifyAcks("/tmp/acks.csv"));
        }
    }
}
