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

    @Test
    void ipv6Prefixes() {
        assertThat(IpPools.prefixes("k.", "2001:db8:100::/40", 42))
                .containsExactly(
                        "2001:db8:100:0:0:0:0:0/42",
                        "2001:db8:140:0:0:0:0:0/42",
                        "2001:db8:180:0:0:0:0:0/42",
                        "2001:db8:1c0:0:0:0:0:0/42");
        assertThat(IpPools.prefixes("k.", "2001:db8:100:ff00::1/56", 56))
                .as("host bits ignored")
                .containsExactly("2001:db8:100:ff00:0:0:0:0/56");
        assertThat(IpPools.prefixes("k.", "2001:db8::/112", 128))
                .hasSize(65536)
                .last()
                .isEqualTo("2001:db8:0:0:0:0:0:ffff/128");
        for (String[] bad : new String[][] {
            {"2001:db8::", "64"},
            {"10.0.0.0/8", "16"},
            {"2001:db8::/40", "39"},
            {"2001:db8::/40", "57"},
            {"host.example/40", "48"},
            {"2001:db8::/0", "8"}
        }) {
            assertThatThrownBy(() -> IpPools.prefixes("k.", bad[0], Integer.parseInt(bad[1])))
                    .as(bad[0] + " " + bad[1])
                    .isInstanceOf(ConfigException.class);
        }
    }

    @Test
    void ipv6PoolConfiguration() {
        IpPools pools = IpPools.from(Config.of(Map.of(
                "auth.pools", "pd, wan, hosts",
                "auth.pool.pd.prefix", "2001:db8:100::/48",
                "auth.pool.pd.length", "56",
                "auth.pool.wan.prefix", "2001:db8:200::/56",
                "auth.pool.wan.attribute", "framed-ipv6-prefix",
                "auth.pool.hosts.prefix", "2001:db8:300::/120",
                "auth.pool.hosts.attribute", "Framed-IPv6-Address",
                "auth.pool.sql.url", "jdbc:postgresql://127.0.0.1:1/none")));
        assertThat(pools.pool("pd").attribute()).isEqualTo("Delegated-IPv6-Prefix");
        assertThat(pools.pool("pd").prefixes()).hasSize(256);
        assertThat(pools.pool("wan").attribute()).isEqualTo("Framed-IPv6-Prefix");
        assertThat(pools.pool("wan").prefixes()).as("/64 by default").hasSize(256);
        assertThat(pools.pool("hosts").prefixes()).hasSize(256);
        for (Map<String, String> bad : java.util.List.of(
                Map.of("auth.pool.p.prefix", "2001:db8::/48", "auth.pool.p.range", "10.0.0.1"),
                Map.of("auth.pool.p.prefix", "2001:db8::/48", "auth.pool.p.attribute", "Framed-IP-Address"),
                Map.of(
                        "auth.pool.p.prefix",
                        "2001:db8::/120",
                        "auth.pool.p.attribute",
                        "Framed-IPv6-Address",
                        "auth.pool.p.length",
                        "124"))) {
            Map<String, String> settings = new java.util.HashMap<>(bad);
            settings.put("auth.pools", "p");
            settings.put("auth.pool.sql.url", "jdbc:x");
            assertThatThrownBy(() -> IpPools.from(Config.of(settings))).isInstanceOf(ConfigException.class);
        }
    }
}
