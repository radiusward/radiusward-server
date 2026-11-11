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
import org.junit.jupiter.api.Test;

/** Identical retransmits hit the gateway cache; changed retransmits are recognised by the cluster. */
@Epic("Accounting")
@Feature("Retransmissions and deduplication")
@Link(
        name = "ADR 0003",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0003-event-key-and-dedup.md")
class RetransmitIT extends E2eTestBase {

    @Test
    void cacheAndClusterDedup() throws Exception {
        int a = cluster.radiusPort("gateway-a");
        int b = cluster.radiusPort("gateway-b");
        byte[] interim = Nas.request(7, 3, "rt-1", 120);
        nas.ack(a, Nas.request(6, 1, "rt-1", 0));
        nas.ack(a, interim);
        nas.ack(a, interim); // identical: answered from the response cache
        assertThat(ProcessCluster.number(cluster.state("gateway-a"), "cache_hits"))
                .isEqualTo(1);

        nas.ack(b, Nas.request(99, 3, "rt-1", 120, 5)); // new Identifier, Acct-Delay-Time, other gateway
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(2);
            assertThat(state.duplicates()).isEqualTo(1);
            long[] key = Nas.sessionKey("rt-1");
            assertThat(admin.session(key[0], key[1]).sessionTime()).isEqualTo(120);
        }
    }
}
