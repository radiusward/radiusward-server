/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.Profile;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GatewayConfigTest {

    @Test
    void defaults() {
        GatewayConfig c = GatewayConfig.from(Config.of(Map.of()));
        assertThat(c.gatewayId()).isEqualTo(1);
        assertThat(c.listenHost()).isEqualTo("0.0.0.0");
        assertThat(c.listenPort()).isEqualTo(1813);
        assertThat(c.socketReceiveBuffer()).isEqualTo(4 << 20);
        assertThat(c.clusterMembers()).containsExactly("localhost", "localhost", "localhost");
        assertThat(c.profile()).isEqualTo(Profile.SMALL);
        assertThat(c.pendingCapacity()).isEqualTo(Profile.SMALL.pendingRequests());
        assertThat(c.pendingTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(c.resubmitAfter()).isEqualTo(Duration.ofSeconds(1));
        assertThat(c.responseCacheTtl()).isEqualTo(Duration.ofSeconds(30));
        assertThat(c.dedicatedThreads()).isFalse();
        assertThat(c.idleStrategy()).isEqualTo("backoff-100us");
        assertThat(c.debugResponseDelay()).isZero();
        assertThat(c.aeronDir()).contains("radiusward-gateway-1-");
    }

    @Test
    void settingsAndProfileDefaults() {
        GatewayConfig c = GatewayConfig.from(Config.of(Map.of(
                "profile", "large",
                "gateway.id", "2",
                "cluster.members", "10.0.0.1,10.0.0.2,10.0.0.3",
                "gateway.listen.port", "1814",
                "gateway.egress.host", "10.0.0.9",
                "debug.enabled", "true",
                "debug.response.delay", "500ms")));
        assertThat(c.gatewayId()).isEqualTo(2);
        assertThat(c.clusterMembers()).isEqualTo(List.of("10.0.0.1", "10.0.0.2", "10.0.0.3"));
        assertThat(c.listenPort()).isEqualTo(1814);
        assertThat(c.egressHost()).isEqualTo("10.0.0.9");
        assertThat(c.dedicatedThreads()).as("large profile").isTrue();
        assertThat(c.idleStrategy()).isEqualTo("busy-spin");
        assertThat(c.debugResponseDelay()).isEqualTo(Duration.ofMillis(500));
    }

    @Test
    void invalidSettingsAreRejected() {
        assertThatThrownBy(() -> GatewayConfig.from(Config.of(Map.of("debug.response.delay", "1s"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("debug.enabled=true");
        assertThatThrownBy(() -> GatewayConfig.from(Config.of(Map.of("gateway.threading", "both"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("shared or dedicated");
        assertThatThrownBy(() -> GatewayConfig.from(Config.of(Map.of("gateway.idle.strategy", "yield"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("backoff-100us");
    }
}
