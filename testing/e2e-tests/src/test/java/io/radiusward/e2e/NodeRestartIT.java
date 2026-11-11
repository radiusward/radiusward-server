/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import java.util.List;
import org.junit.jupiter.api.Test;

/** A follower killed with -9 catches up from the log after restart. */
@Epic("Cluster")
@Feature("Member restart")
class NodeRestartIT extends E2eTestBase {

    @Test
    void followerCatchesUp() throws Exception {
        String leader = cluster.awaitLeader();
        String follower = List.of("node-0", "node-1", "node-2").stream()
                .filter(n -> !n.equals(leader))
                .findFirst()
                .orElseThrow();
        cluster.kill(follower);
        int port = cluster.radiusPort("gateway-a");
        for (int i = 0; i < 50; i++) {
            nas.ack(port, Nas.request(i, 1, "nr-" + i, 0));
        }
        cluster.start(follower);
        cluster.awaitReady(follower);
        cluster.awaitConverged();
        assertThat(ProcessCluster.number(cluster.state(follower), "applied")).isEqualTo(50);
    }
}
