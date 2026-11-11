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
import java.util.List;
import org.junit.jupiter.api.Test;

/** No majority, no Accounting-Response; once a majority is back the retransmit is acknowledged exactly once. */
@Epic("Accounting")
@Feature("Acknowledged only after commit")
@Link(
        name = "ADR 0002",
        url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0002-ack-boundary.md")
class AckAfterCommitIT extends E2eTestBase {

    @Test
    void noAckWithoutMajority() throws Exception {
        int port = cluster.radiusPort("gateway-a");
        nas.ack(port, Nas.request(1, 1, "ack-1", 0));

        String leader = cluster.awaitLeader();
        List<String> others = List.of("node-0", "node-1", "node-2").stream()
                .filter(n -> !n.equals(leader))
                .toList();
        cluster.kill(others.get(0));
        cluster.kill(others.get(1));

        byte[] interim = Nas.request(2, 3, "ack-1", 60);
        assertThat(nas.exchange(port, interim, 3, Duration.ofSeconds(3)))
                .as("a single member cannot commit, so it must not acknowledge")
                .isNull();

        cluster.start(others.get(0));
        cluster.awaitReady(others.get(0));
        assertThat(nas.ack(port, interim)).isNotNull();
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            assertThat(admin.state().applied()).as("start + interim, each once").isEqualTo(2);
            long[] key = Nas.sessionKey("ack-1");
            assertThat(admin.session(key[0], key[1]).sessionTime()).isEqualTo(60);
        }
    }
}
