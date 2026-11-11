/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.tools.admin.AdminClient;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Gateway dies after the cluster committed but before it answered: the retry via the other gateway is a duplicate. */
@Epic("Cluster")
@Feature("Gateway failover")
@Link(
        name = "ADR 0003",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0003-event-key-and-dedup.md")
class GatewayFailoverIT extends E2eTestBase {

    @Override
    void configure(ProcessCluster cluster) throws Exception {
        cluster.gatewayConfig("gateway-a", "debug.enabled=true\ndebug.response.delay=5s\n");
    }

    @Test
    void retryThroughOtherGateway() throws Exception {
        byte[] start = Nas.request(1, 1, "gw-1", 0);
        assertThat(nas.exchange(cluster.radiusPort("gateway-a"), start, 1, Duration.ofSeconds(2)))
                .isNull();
        cluster.awaitConverged(); // committed, the answer is held back by the debug delay
        cluster.kill("gateway-a");

        assertThat(nas.ack(cluster.radiusPort("gateway-b"), start)).isNotNull();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(1);
            assertThat(state.duplicates()).isEqualTo(1);
        }
    }
}
