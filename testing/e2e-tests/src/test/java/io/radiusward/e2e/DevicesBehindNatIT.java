/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.SessionStatus;
import io.radiusward.tools.admin.AdminClient;
import org.junit.jupiter.api.Test;

/**
 * Access points behind one address (ADR 0019): the NAS entry identifies them by NAS-Identifier, so equal
 * Acct-Session-Ids stay separate sessions and an Accounting-On stops only the rebooted device's sessions.
 */
class DevicesBehindNatIT extends E2eTestBase {

    @Override
    void configure(ProcessCluster cluster) throws Exception {
        cluster.nasConfig("nas.local.identity=nas-identifier");
    }

    @Test
    void accountingOnStopsOnlyTheRebootedDevicesSessions() throws Exception {
        int a = cluster.radiusPort("gateway-a");
        int b = cluster.radiusPort("gateway-b");
        nas.ack(a, Nas.request(1, 1, "00000001", 0, 0, "ap-1"));
        nas.ack(b, Nas.request(2, 1, "00000001", 0, 0, "ap-2")); // same id, other device, other gateway
        nas.ack(a, Nas.request(3, 1, "00000002", 0, 0, "ap-1"));
        nas.ack(b, Nas.request(4, 7, null, 0, 0, "ap-1")); // ap-1 reboots
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            long[] ap1 = Nas.sessionKey("00000001", "ap-1");
            long[] ap2 = Nas.sessionKey("00000001", "ap-2");
            assertThat(admin.session(ap1[0], ap1[1]).status()).isEqualTo(SessionStatus.STOPPED);
            assertThat(admin.session(ap2[0], ap2[1]).status()).isEqualTo(SessionStatus.ACTIVE);
            AdminClient.State state = admin.state();
            assertThat(state.active()).isEqualTo(1);
            assertThat(state.stopped()).isEqualTo(2);
        }
    }
}
