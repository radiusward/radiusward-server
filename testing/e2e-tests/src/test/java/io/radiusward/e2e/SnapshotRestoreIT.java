/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.testing.AdminClient;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** After a snapshot and a restart of every member, old events are still recognised as duplicates. */
class SnapshotRestoreIT extends E2eTestBase {

    @Test
    void dedupSurvivesFullRestart() throws Exception {
        int port = cluster.radiusPort("gateway-a");
        for (int i = 0; i < 20; i++) {
            nas.ack(port, Nas.request(i, 1, "sr-" + i, 0));
        }
        cluster.awaitConverged();
        String leader = cluster.awaitLeader();
        Process tool = new ProcessBuilder(
                        ProcessHandle.current().info().command().orElse("java"),
                        "-jar",
                        cluster.jar().toString(),
                        "cluster-tool",
                        cluster.clusterDir(leader).toString(),
                        "snapshot")
                .redirectErrorStream(true)
                .redirectOutput(cluster.dir().resolve("clustertool.log").toFile())
                .start();
        assertThat(tool.waitFor(60, TimeUnit.SECONDS)).isTrue();
        assertThat(tool.exitValue())
                .as("ClusterTool snapshot (see clustertool.log)")
                .isZero();

        for (String n : List.of("node-0", "node-1", "node-2")) {
            cluster.stop(n);
        }
        for (String n : List.of("node-0", "node-1", "node-2")) {
            cluster.start(n);
        }
        for (String n : List.of("node-0", "node-1", "node-2")) {
            cluster.awaitReady(n);
        }
        cluster.awaitConverged();
        for (int i = 0; i < 20; i++) {
            nas.ack(port, Nas.request(100 + i, 1, "sr-" + i, 0)); // new identifiers: the gateway cache cannot help
        }
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(20);
            assertThat(state.duplicates()).isGreaterThanOrEqualTo(20);
        }
    }
}
