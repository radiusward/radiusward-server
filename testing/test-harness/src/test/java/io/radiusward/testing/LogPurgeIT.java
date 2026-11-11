/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.node.LogPurgeConfig;
import io.radiusward.tools.radclient.LoadGenerator;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * ADR 0014 in a real cluster with 4 MiB archive segments and a 1 s purge interval: after two snapshots every
 * member's log starts beyond 0 (bounded by the second-latest snapshot), and a member stopped before a purge
 * catches up again afterwards.
 */
@Epic("Cluster")
@Feature("Log purge")
@Link(name = "ADR 0014", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0014-log-purge.md")
class LogPurgeIT {

    private static final Pattern LOG_START = Pattern.compile("\"logStart\":(\\d+)");

    @TempDir
    Path dir;

    @Test
    void logIsPurgedAndAStoppedMemberStillCatchesUp() throws Exception {
        try (LocalCluster cluster = LocalCluster.start(
                dir.toFile(),
                3,
                2,
                LocalCluster.freePortBase(3),
                new int[2],
                Duration.ZERO,
                id -> io.radiusward.exporter.ExportConfig.NONE,
                // from the first start: the log recording keeps the segment length it was created with
                new LogPurgeConfig(true, false, 4 << 20, Duration.ofSeconds(1)))) {
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();

            load(cluster, 0);
            snapshot(cluster, 1);
            load(cluster, 100_000);
            snapshot(cluster, 2);
            load(cluster, 200_000);
            try {
                LocalCluster.await(Duration.ofSeconds(60), "every member purged", () -> {
                    for (int i = 0; i < 3; i++) {
                        if (logStart(cluster.node(i)) <= 0) {
                            return false;
                        }
                    }
                    return true;
                });
            } catch (AssertionError e) {
                for (int i = 0; i < 3; i++) {
                    System.out.println(
                            "member " + i + " state: " + cluster.node(i).stateJson());
                }
                throw e;
            }
            for (int i = 0; i < 3; i++) {
                System.out.println("member " + i + " after purge: "
                        + section(cluster.node(i).stateJson(), "\"logPurge\":"));
            }

            // a member that misses the next purge must still catch up from the others' logs
            int follower = (cluster.awaitLeader().config().nodeId() + 1) % 3;
            cluster.stopNode(follower);
            load(cluster, 300_000);
            snapshot(cluster, 3);
            load(cluster, 400_000);
            snapshot(cluster, 4);
            Thread.sleep(3_000); // purge ticks while the follower is away
            cluster.startNode(follower);
            cluster.awaitConverged();
            assertThat(cluster.node(follower).stats().applied())
                    .isEqualTo(cluster.awaitLeader().stats().applied());
        }
    }

    static long logStart(ClusterNode node) {
        Matcher m = LOG_START.matcher(node.stateJson());
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }

    static void snapshot(LocalCluster cluster, int expected) {
        ClusterNode leader = cluster.awaitLeader();
        LocalCluster.await(Duration.ofSeconds(10), "snapshot requested", leader::requestSnapshot);
        LocalCluster.await(
                Duration.ofSeconds(30),
                "snapshot " + expected,
                () -> leader.stats().snapshots() >= expected);
    }

    static void load(LocalCluster cluster, int firstSession) {
        Reports.step("load: 3000 sessions from session " + firstSession, () -> runLoad(cluster, firstSession));
    }

    private static void runLoad(LocalCluster cluster, int firstSession) {
        try {
            LoadGenerator.Result result = new LoadGenerator(
                            new LoadGenerator.Settings(
                                    List.of(
                                            new InetSocketAddress(
                                                    "127.0.0.1",
                                                    cluster.gateway(0).radiusPort()),
                                            new InetSocketAddress(
                                                    "127.0.0.1",
                                                    cluster.gateway(1).radiusPort())),
                                    LocalClusterIT.SECRET,
                                    10,
                                    3000,
                                    3000,
                                    Duration.ofSeconds(6),
                                    Duration.ofSeconds(1),
                                    Duration.ofSeconds(3),
                                    4,
                                    true,
                                    true,
                                    null,
                                    firstSession),
                            new PrintStream(System.out))
                    .run();
            Reports.attach("radclient load", result.toString());
            if (result.failed() > 0) {
                cluster.gateways().forEach(g -> System.out.println("gateway after failed load: " + g.stateJson()));
            }
            assertThat(result.failed()).isZero();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The JSON object after {@code key} in {@code json} (diagnostic output). */
    private static String section(String json, String key) {
        int at = json.indexOf(key);
        if (at < 0) {
            return json;
        }
        int end = json.indexOf('}', at);
        return json.substring(at + key.length(), end < 0 ? json.length() : end + 1);
    }
}
