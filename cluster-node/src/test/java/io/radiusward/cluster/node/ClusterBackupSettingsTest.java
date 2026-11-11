/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aeron.cluster.ClusterBackup;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Settings of the cluster backup and the restore command's checks (ADR 0065). */
class ClusterBackupSettingsTest {

    @TempDir
    Path dir;

    @Test
    void defaultsAndTheMembersConsensusEndpoints() {
        ClusterBackupNode.Settings s = ClusterBackupNode.Settings.from(Config.of(
                Map.of("cluster.members", "m0,m1,m2", "cluster.base.port", "9000", "archive.segment.length", "4m")));
        assertThat(s.members()).isEqualTo(List.of("m0", "m1", "m2"));
        assertThat(s.host()).isEqualTo("localhost");
        assertThat(s.port()).isEqualTo(9900);
        assertThat(s.source()).isEqualTo(ClusterBackup.SourceType.FOLLOWER);
        assertThat(s.interval()).isEqualTo(Duration.ofMinutes(30));
        assertThat(s.segmentLength()).isEqualTo(4 << 20);
        assertThat(s.dataDir().getPath()).endsWith("backup");
        assertThat(s.consensusEndpoints()).isEqualTo("m0:9001,m1:9101,m2:9201");
    }

    @Test
    void sourceAndPortsAreConfigurable() {
        ClusterBackupNode.Settings s = ClusterBackupNode.Settings.from(Config.of(Map.of(
                "backup.source", "any", "backup.host", "10.0.0.9", "backup.port", "7000", "backup.interval", "5m")));
        assertThat(s.source()).isEqualTo(ClusterBackup.SourceType.ANY);
        assertThat(s.host()).isEqualTo("10.0.0.9");
        assertThat(s.port()).isEqualTo(7000);
        assertThat(s.interval()).isEqualTo(Duration.ofMinutes(5));
        assertThatThrownBy(() -> ClusterBackupNode.Settings.from(Config.of(Map.of("backup.source", "nearest"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("backup.source");
    }

    @Test
    void restoreRefusesWhatIsNoBackupAndAMemberWithData() throws Exception {
        assertThatThrownBy(() -> ClusterRestore.main(new String[] {"--config", "x.properties"}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("--from");
        Path props = dir.resolve("cluster.properties");
        Files.writeString(props, "cluster.node.id=0\ncluster.data.dir=" + dir.resolve("data") + "\n");
        assertThatThrownBy(() -> ClusterRestore.main(
                        new String[] {"--from", dir.resolve("nothing").toString(), "--config", props.toString()}))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a cluster backup");

        ClusterNodeConfig member = ClusterNodeConfig.from(Config.of(Map.of(
                "cluster.node.id", "0", "cluster.data.dir", dir.resolve("data").toString())));
        Files.createDirectories(member.dataDir().toPath().resolve("cluster"));
        Files.writeString(member.dataDir().toPath().resolve("cluster/recording.log"), "");
        assertThatThrownBy(() -> ClusterRestore.restore(dir.resolve("nothing"), member))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not empty");
    }
}
