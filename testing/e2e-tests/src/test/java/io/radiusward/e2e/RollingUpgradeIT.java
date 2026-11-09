/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.testing.LocalCluster;
import io.radiusward.tools.admin.AdminClient;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Rolling upgrade (ADR 0005): members restarted one by one with a release that knows a newer state version keep
 * applying the old one; when the last member runs it, the cluster activates it by itself, on all members at the same
 * log position. A member then started with the older release stops instead of applying entries wrongly. The newer
 * release is simulated with {@code debug.state.version.supported}.
 */
class RollingUpgradeIT extends E2eTestBase {

    static final int OLD = AccountingStateMachine.STATE_VERSION;
    static final int NEW = OLD + 1;

    @Override
    void configure(ProcessCluster cluster) throws Exception {
        cluster.clusterConfig("log.purge.interval=1s"); // members report their version every second
    }

    private int activeVersion() {
        try (AdminClient admin = cluster.admin()) {
            return admin.state().activeVersion();
        }
    }

    @Test
    void theLastUpgradedMemberActivatesTheNewVersionEverywhere() throws Exception {
        int port = cluster.radiusPort("gateway-a");
        nas.ack(port, Nas.request(1, 1, "up-1", 0));
        // a fresh cluster first activates what all members run (above the first release's baseline)
        LocalCluster.await(Duration.ofSeconds(30), "the current version active", () -> activeVersion() == OLD);
        for (String node : new String[] {"node-0", "node-1", "node-2"}) {
            cluster.stop(node);
            cluster.nodeConfig(node, "debug.enabled=true\ndebug.state.version.supported=" + NEW);
            cluster.start(node);
            cluster.awaitReady(node);
            cluster.awaitConverged();
            nas.ack(port, Nas.request(10 + node.charAt(5), 3, "up-1", 60L * (node.charAt(5) - '0' + 1)));
            if (!node.equals("node-2")) {
                Thread.sleep(3_000); // several reports: still only some members know NEW
                assertThat(activeVersion()).as("after upgrading %s", node).isEqualTo(OLD);
            }
        }
        LocalCluster.await(Duration.ofSeconds(30), "automatic activation", () -> activeVersion() == NEW);
        cluster.awaitConverged(); // same digest on all members: they switched at the same position
        for (String node : new String[] {"node-0", "node-1", "node-2"}) {
            assertThat(ProcessCluster.number(cluster.state(node), "stateVersionActive"))
                    .isEqualTo(NEW);
        }
        nas.ack(port, Nas.request(20, 2, "up-1", 600)); // accounting goes on

        // a rollback of one member to the old release after activation: it must stop, not diverge
        cluster.stop("node-2");
        cluster.nodeConfig("node-2", "");
        cluster.start("node-2");
        LocalCluster.await(
                Duration.ofSeconds(60),
                "node-2 refuses the newer active version",
                () -> cluster.logTail("node-2").contains("applies state version " + NEW));
        assertThat(cluster.ready("node-2"))
                .as("not ready: " + cluster.readiness("node-2"))
                .isFalse();
        nas.ack(port, Nas.request(21, 1, "up-2", 0)); // the other two members still form a majority
    }
}
