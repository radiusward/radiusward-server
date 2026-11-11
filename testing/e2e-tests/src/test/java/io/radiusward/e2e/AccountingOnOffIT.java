/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.tools.admin.AdminClient;
import org.junit.jupiter.api.Test;

/** Accounting-On from a rebooted NAS closes its open sessions. */
@Epic("Accounting")
@Feature("Accounting-On/Off")
class AccountingOnOffIT extends E2eTestBase {

    @Test
    void accountingOnStopsSessions() throws Exception {
        int port = cluster.radiusPort("gateway-a");
        for (int i = 0; i < 3; i++) {
            nas.ack(port, Nas.request(i, 1, "on-" + i, 0));
        }
        nas.ack(port, Nas.request(10, 7, null, 0));
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.active()).isZero();
            assertThat(state.stopped()).isEqualTo(3);
        }
    }
}
