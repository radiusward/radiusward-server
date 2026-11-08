/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.Container.ExecResult;

/**
 * Small profile at its limits (ADR 0004), with the exporter and its state-machine replica exporting to PostgreSQL: members limited to 1 GiB and one CPU, gateways to 384 MiB, 2M sessions
 * (the profile's maximum), 8 generators offering 48k requests/s for 2 minutes. Measured on an 8-CPU Colima VM:
 * ~32k/s served, so the gateways must shed load (pending table full; the NAS retries). Nothing may be
 * OOM-killed, unreclaimable memory stays below the limit, every event is acknowledged eventually and the
 * replicas are consistent afterwards.
 */
class OverloadIT {

    private static final int GENERATORS = 8;
    private static final int SESSIONS_EACH = 250_000;
    private static final int RATE_EACH = 6000;

    @Test
    void smallProfileShedsLoadWithoutRunningOutOfMemory() {
        try (ContainerCluster cluster = new ContainerCluster(
                "overload", ContainerCluster.Options.defaults().postgres(true))) {
            cluster.start();
            List<ContainerCluster.Member> all = new ArrayList<>(cluster.nodes());
            all.addAll(cluster.gateways());
            Map<String, Long> maxUnreclaimable = new HashMap<>();
            AtomicBoolean running = new AtomicBoolean(true);
            CompletableFuture<Void> sampler = CompletableFuture.runAsync(() -> {
                while (running.get()) {
                    for (ContainerCluster.Member m : all) {
                        if (cluster.running(m)) {
                            maxUnreclaimable.merge(m.name(), cluster.memory(m).unreclaimable(), Math::max);
                        }
                    }
                    ContainerCluster.sleep(2_000);
                }
            });

            List<CompletableFuture<ExecResult>> loads = new ArrayList<>();
            for (int g = 0; g < GENERATORS; g++) {
                int first = g * SESSIONS_EACH;
                loads.add(CompletableFuture.supplyAsync(() -> cluster.radiusward(
                        "radclient",
                        "load",
                        "--server",
                        ContainerCluster.GATEWAYS,
                        "--secret",
                        ContainerCluster.SECRET,
                        "--nas",
                        "100",
                        "--sessions",
                        Integer.toString(SESSIONS_EACH),
                        "--first-session",
                        Integer.toString(first),
                        "--rate",
                        Integer.toString(RATE_EACH),
                        "--duration",
                        "120s",
                        "--interim",
                        "60s",
                        "--no-stop")));
            }
            long acked = 0;
            for (CompletableFuture<ExecResult> load : loads) {
                ExecResult r = load.join();
                System.out.println(r.getStdout()
                        .lines()
                        .filter(l -> l.startsWith("load:"))
                        .findFirst()
                        .orElse(r.getStdout() + r.getStderr()));
                acked += LoadResult.parse(r.getStdout()).acked();
            }
            running.set(false);
            sampler.join();

            System.out.println("overload: acked " + acked + " in total");
            for (ContainerCluster.Member m : all) {
                ContainerCluster.Memory mem = cluster.memory(m);
                System.out.printf(
                        "%s: max unreclaimable %d MiB; now %s%n", m.name(), maxUnreclaimable.get(m.name()) >> 20, mem);
                assertThat(cluster.oomKilled(m)).as(m.name() + " OOM-killed").isFalse();
                assertThat(cluster.running(m)).as(m.name() + " running").isTrue();
                assertThat(maxUnreclaimable.get(m.name()))
                        .as(m.name() + " heap + native + /dev/shm")
                        .isLessThan(mem.limit());
            }
            long dropped = 0;
            for (ContainerCluster.Member g : cluster.gateways()) {
                Map<String, String> s = cluster.state(g);
                System.out.println(g.name() + ": " + s);
                dropped += Long.parseLong(s.get("ring_full"))
                        + Long.parseLong(s.get("pending_full"))
                        + Long.parseLong(s.get("back_pressured"));
            }
            System.out.println("overload: gateways dropped or back-pressured " + dropped);
            assertThat(dropped)
                    .as("the gateways had to shed load, or this was no overload")
                    .isPositive();
            cluster.awaitConverged(Duration.ofSeconds(120));
            Map<String, String> leader = cluster.state(cluster.awaitLeader(Duration.ofSeconds(5)));
            System.out.println("overload: leader " + leader);
            assertThat(Long.parseLong(leader.get("activeSessions"))).isPositive();
        }
    }
}
