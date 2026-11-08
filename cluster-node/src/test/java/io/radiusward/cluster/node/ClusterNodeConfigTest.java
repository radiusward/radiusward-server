/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ClusterNodeConfigTest {

    private static final Map<String, String> NODE = Map.of("cluster.node.id", "1");

    @Test
    void defaults() {
        ClusterNodeConfig c = ClusterNodeConfig.from(Config.of(NODE));
        assertThat(c.nodeId()).isEqualTo(1);
        assertThat(c.members()).hasSize(3);
        assertThat(c.basePort()).isEqualTo(9000);
        assertThat(c.dataDir().getPath()).endsWith("node-1");
        assertThat(c.leaderHeartbeatTimeout()).isEqualTo(Duration.ofMillis(1500));
        assertThat(c.electionTimeout()).isEqualTo(Duration.ofMillis(500));
        assertThat(c.sessionTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(c.snapshotInterval()).isEqualTo(Duration.ofHours(1));
        assertThat(c.fileSyncLevel()).isEqualTo(2);
        assertThat(c.diskMinFree()).isEqualTo(1L << 30);
        assertThat(c.maxClientSessions()).isEqualTo(256);
        assertThat(c.export().enabled()).isFalse();
        assertThat(c.purge()).isEqualTo(LogPurgeConfig.DEFAULTS);
    }

    @Test
    void portsAndMemberStrings() {
        ClusterNodeConfig c = ClusterNodeConfig.from(
                Config.of(Map.of("cluster.node.id", "2", "cluster.members", "a,b,c", "cluster.base.port", "7000")));
        assertThat(c.host()).isEqualTo("c");
        assertThat(c.port(2, ClusterNodeConfig.ARCHIVE_CONTROL_OFFSET)).isEqualTo(7204);
        assertThat(c.clusterMembers()).startsWith("0,a:7000,a:7001,a:7002,a:7003,a:7004|1,b:7100");
        assertThat(ClusterNodeConfig.ingressEndpoints(List.of("a", "b", "c"), 7000))
                .isEqualTo("0=a:7000,1=b:7100,2=c:7200");
    }

    @Test
    void purgeAndExportSettings() {
        ClusterNodeConfig c = ClusterNodeConfig.from(Config.of(Map.of(
                "cluster.node.id", "0",
                "archive.segment.length", "4m",
                "log.purge.dry.run", "true",
                "log.purge.interval", "10s",
                "export.sinks", "pg",
                "sink.pg.type", "postgres")));
        assertThat(c.purge()).isEqualTo(new LogPurgeConfig(true, true, 4 << 20, Duration.ofSeconds(10)));
        assertThat(c.export().enabled()).isTrue();
        assertThat(c.export().sinks().get(0).name()).isEqualTo("pg");
    }

    @Test
    void invalidSettingsAreRejected() {
        assertThatThrownBy(() -> ClusterNodeConfig.from(Config.of(Map.of("cluster.node.id", "3"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("not an index into cluster.members");
        assertThatThrownBy(() -> ClusterNodeConfig.from(
                        Config.of(Map.of("cluster.node.id", "0", "archive.file.sync.level", "3"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("expected 0, 1 or 2");
        assertThatThrownBy(() -> ClusterNodeConfig.from(
                        Config.of(Map.of("cluster.node.id", "0", "archive.segment.length", "3m"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("power of two");
        assertThatThrownBy(() -> ClusterNodeConfig.from(Config.of(Map.of()))).isInstanceOf(ConfigException.class);
    }
}
