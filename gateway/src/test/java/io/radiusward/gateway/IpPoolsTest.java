/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IpPoolsTest {

    @Test
    void ranges() {
        assertThat(IpPools.range("k", "10.0.0.10-10.0.0.20")).containsExactly(0x0A00000AL, 0x0A000014L);
        assertThat(IpPools.range("k", "10.0.1.0/24"))
                .as("without network and broadcast")
                .containsExactly(0x0A000101L, 0x0A0001FEL);
        assertThat(IpPools.range("k", "10.0.1.6/31")).containsExactly(0x0A000106L, 0x0A000107L);
        assertThat(IpPools.range("k", "192.168.0.1")).containsExactly(0xC0A80001L, 0xC0A80001L);
        assertThat(IpPools.text(0xC0A80001L)).isEqualTo("192.168.0.1");
        for (String bad :
                new String[] {"10.0.0.20-10.0.0.10", "10.0.0/24", "10.0.0.0/8", "10.0.0.256", "x", "1.2.3.0001"}) {
            assertThatThrownBy(() -> IpPools.range("k", bad)).as(bad).isInstanceOf(ConfigException.class);
        }
    }

    @Test
    void configuration() {
        assertThat(IpPools.from(Config.of(Map.of()))).isNull();
        IpPools pools = IpPools.from(Config.of(Map.of(
                "auth.pools", "office",
                "auth.pool.office.range", "10.0.0.1-10.0.0.9, 10.0.1.0/30",
                "auth.pool.office.lease", "90s",
                "auth.pool.office.exhausted", "accept",
                "auth.pool.sql.url", "jdbc:postgresql://127.0.0.1:1/none"))); // unreachable: a warning only
        IpPools.Pool office = pools.pool(" office ");
        assertThat(office.lease()).isEqualTo(Duration.ofSeconds(90));
        assertThat(office.exhausted()).isTrue();
        assertThat(office.ranges()).hasSize(2);
        assertThat(pools.pool("other")).isNull();
        assertThatThrownBy(() -> IpPools.from(Config.of(Map.of(
                        "auth.pools", "big", "auth.pool.big.range", "10.0.0.0/15", "auth.pool.sql.url", "jdbc:x"))))
                .isInstanceOf(ConfigException.class);
        assertThatThrownBy(() -> IpPools.from(Config.of(Map.of("auth.pools", "none", "auth.pool.sql.url", "jdbc:x"))))
                .isInstanceOf(ConfigException.class);
        assertThatThrownBy(() -> IpPools.from(Config.of(Map.of(
                        "auth.pools", "p",
                        "auth.pool.p.range", "10.0.0.1",
                        "auth.pool.p.exhausted", "maybe",
                        "auth.pool.sql.url", "jdbc:x"))))
                .isInstanceOf(ConfigException.class);
    }
}
