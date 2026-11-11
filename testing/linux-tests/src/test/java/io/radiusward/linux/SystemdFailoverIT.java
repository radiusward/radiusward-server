/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * The systemd units of {@code deploy/systemd}, unchanged, with systemd as PID 1 in every container
 * ({@code docs/operations/bare-metal.md}): under load the leader's member is killed and {@code Restart=on-failure}
 * brings it back, a follower is stopped and started, a gateway is reloaded (SIGHUP) and another one drains before it
 * stops. No acknowledged event is lost and every unit ends {@code active}.
 */
@Epic("Fault injection")
@Feature("systemd units")
class SystemdFailoverIT {

    @Test
    void unitsRestartReloadAndDrainWithoutLosingAcknowledgedEvents() {
        try (ContainerCluster cluster = new ContainerCluster(
                "systemd-failover", ContainerCluster.Options.defaults().systemd(true))) {
            cluster.start();
            CompletableFuture<LoadResult> load = CompletableFuture.supplyAsync(
                    () -> cluster.load(10, 3_000, 300, Duration.ofSeconds(100), "/tmp/acks.csv"));

            // 1. the leader's process dies: systemd restarts it (RestartSec=2s) and it rejoins
            ContainerCluster.sleep(10_000);
            ContainerCluster.Member leader = cluster.awaitLeader(Duration.ofSeconds(10));
            Reports.step("systemctl kill --signal=SIGKILL radiusward-node on " + leader.name(), () -> {
                assertThat(cluster.systemctl(
                                        leader,
                                        "kill",
                                        "--kill-whom=main",
                                        "--signal=SIGKILL",
                                        ContainerCluster.NODE_UNIT)
                                .getExitCode())
                        .isZero();
            });
            cluster.awaitLeaderOtherThan(leader, Duration.ofSeconds(10));
            cluster.awaitReady(java.util.List.of(leader), Duration.ofSeconds(60));
            assertThat(cluster.unitRestarts(leader))
                    .as("restarted by Restart=on-failure")
                    .isEqualTo(1);

            // 2. a follower stopped and started like an operator would, the unit ends inactive (not failed) first
            ContainerCluster.Member leaderNow = cluster.awaitLeader(Duration.ofSeconds(10));
            ContainerCluster.Member follower = cluster.nodes().stream()
                    .filter(n -> n != leaderNow)
                    .findFirst()
                    .orElseThrow();
            Reports.step("systemctl stop, then start radiusward-node on " + follower.name(), () -> {
                assertThat(cluster.systemctl(follower, "stop", ContainerCluster.NODE_UNIT)
                                .getExitCode())
                        .isZero();
                assertThat(cluster.unitState(follower))
                        .as("a clean stop is not a failure (SuccessExitStatus=143)")
                        .isEqualTo("inactive");
                ContainerCluster.sleep(5_000);
                assertThat(cluster.systemctl(follower, "start", ContainerCluster.NODE_UNIT)
                                .getExitCode())
                        .isZero();
            });
            cluster.awaitReady(java.util.List.of(follower), Duration.ofSeconds(60));

            // 3. configuration reload of a gateway: SIGHUP, the gateway keeps answering
            ContainerCluster.Member reloaded = cluster.gateways().get(0);
            Reports.step("systemctl reload radiusward-gateway on " + reloaded.name(), () -> {
                assertThat(cluster.systemctl(reloaded, "reload", ContainerCluster.GATEWAY_UNIT)
                                .getExitCode())
                        .isZero();
                assertThat(cluster.unitState(reloaded)).isEqualTo("active");
            });

            // 4. a gateway stopped: not ready while it drains (5 s), then inactive; started again
            ContainerCluster.Member stopped = cluster.gateways().get(1);
            Reports.step("systemctl stop radiusward-gateway on " + stopped.name() + " (drain), then start", () -> {
                assertThat(cluster.systemctl(stopped, "stop", "--no-block", ContainerCluster.GATEWAY_UNIT)
                                .getExitCode())
                        .isZero();
                ContainerCluster.sleep(1_000);
                assertThat(cluster.unitState(stopped)).as("still draining").isEqualTo("deactivating");
                assertThat(cluster.ready(stopped))
                        .as("not ready while draining")
                        .isFalse();
                long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
                while (!cluster.unitState(stopped).equals("inactive")) {
                    assertThat(System.nanoTime())
                            .as("gateway stopped within 30 s")
                            .isLessThan(deadline);
                    ContainerCluster.sleep(500);
                }
                assertThat(cluster.systemctl(stopped, "start", ContainerCluster.GATEWAY_UNIT)
                                .getExitCode())
                        .isZero();
            });
            cluster.awaitReady(cluster.gateways(), Duration.ofSeconds(60));

            LoadResult result = load.join();
            assertThat(result.failed()).as("unacknowledged events").isZero();
            cluster.awaitConverged(Duration.ofSeconds(60));
            assertThat(cluster.verifyAcks("/tmp/acks.csv").getExitCode()).isZero();
            for (ContainerCluster.Member m : cluster.nodes()) {
                assertThat(cluster.unitState(m)).as(m.name()).isEqualTo("active");
            }
            for (ContainerCluster.Member g : cluster.gateways()) {
                assertThat(cluster.unitState(g)).as(g.name()).isEqualTo("active");
            }
        }
    }
}
