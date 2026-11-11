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
 * The leader's data directory fills up under load (400 MiB tmpfs, warning below 100 MiB).
 *
 * <ol>
 *   <li>Below {@code cluster.disk.min.free} the member reports not ready, with the reason: the early warning.
 *   <li>Completely full: the member stops (measured: SIGBUS on a write to a memory-mapped file, so the JVM dies)
 *       and the majority elects a new leader; it never acknowledges anything it could not write.
 *   <li>The member is replaced with an empty disk and catches up; no acknowledged event is lost.
 * </ol>
 */
@Epic("Fault injection")
@Feature("Full disk")
@Link(
        name = "ADR 0016",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0016-fault-injection-tests.md")
class DiskFullIT {

    private static final String DATA = "/var/lib/radiusward";

    @Test
    void fullDiskStopsTheMemberWithoutLosingAcknowledgedEvents() {
        try (ContainerCluster cluster = new ContainerCluster(
                "disk-full", ContainerCluster.Options.defaults().dataTmpfsMib(400))) {
            cluster.start();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 2500, 500, Duration.ofSeconds(40), "/tmp/acks.csv"));
            ContainerCluster.sleep(8_000);
            ContainerCluster.Member leader = cluster.awaitLeader(Duration.ofSeconds(5));

            // leave ~60 MiB: below the 100 MiB threshold, not yet full
            cluster.shell(
                    leader,
                    "free=$(df -m " + DATA + " | awk 'NR==2 {print $4}'); " + "dd if=/dev/zero of=" + DATA
                            + "/filler-1 bs=1M count=$((free - 60)) 2>/dev/null");
            ContainerCluster.sleep(1_000);
            String probe = cluster.radiusward("probe", "http://" + leader.ip() + ":9090/ready")
                    .getStdout();
            assertThat(probe).as("readiness of the leader").contains("low disk space");
            assertThat(cluster.state(leader)).containsKey("diskFreeBytes");

            cluster.shell(leader, "dd if=/dev/zero of=" + DATA + "/filler-2 bs=1M 2>/dev/null");
            ContainerCluster.Member next = cluster.awaitLeaderOtherThan(leader, Duration.ofSeconds(20));
            System.out.println("disk full: " + leader.name() + " running=" + cluster.running(leader) + ", new leader "
                    + next.name());

            // replace the member: a fresh container start gets an empty tmpfs
            if (cluster.running(leader)) {
                cluster.kill(leader);
            }
            cluster.restart(leader);
            LoadResult result = load.join();
            assertThat(result.acked()).isPositive();
            cluster.awaitReady(cluster.nodes(), Duration.ofSeconds(90));
            cluster.awaitConverged(Duration.ofSeconds(90));
            assertThat(cluster.verifyAcks("/tmp/acks.csv").getExitCode())
                    .as("no acknowledged event lost")
                    .isZero();
        }
    }
}
