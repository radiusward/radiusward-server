/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.common.Profile;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.exporter.ExportConfig;
import java.io.File;
import java.time.Duration;
import java.util.List;

/**
 * Settings of one cluster member, read from properties (see {@code docs/configuration.md}).
 *
 * <p>Ports: member {@code i} uses {@code basePort + 100·i + offset} with offsets ingress 0, consensus 1,
 * log 2, catchup 3, archive control 4, archive replication 5.
 */
public record ClusterNodeConfig(
        int nodeId,
        List<String> members,
        int basePort,
        File dataDir,
        String aeronDir,
        Profile profile,
        Duration leaderHeartbeatTimeout,
        Duration electionTimeout,
        Duration sessionTimeout,
        Duration snapshotInterval,
        int fileSyncLevel,
        long diskMinFree,
        int maxClientSessions,
        AccountingStateMachine.Settings serviceSettings,
        Duration sweepInterval,
        ExportConfig export,
        LogPurgeConfig purge,
        boolean versionHold) {

    /** Without {@code cluster.version.hold}. */
    public ClusterNodeConfig(
            int nodeId,
            List<String> members,
            int basePort,
            File dataDir,
            String aeronDir,
            Profile profile,
            Duration leaderHeartbeatTimeout,
            Duration electionTimeout,
            Duration sessionTimeout,
            Duration snapshotInterval,
            int fileSyncLevel,
            long diskMinFree,
            int maxClientSessions,
            AccountingStateMachine.Settings serviceSettings,
            Duration sweepInterval,
            ExportConfig export,
            LogPurgeConfig purge) {
        this(
                nodeId,
                members,
                basePort,
                dataDir,
                aeronDir,
                profile,
                leaderHeartbeatTimeout,
                electionTimeout,
                sessionTimeout,
                snapshotInterval,
                fileSyncLevel,
                diskMinFree,
                maxClientSessions,
                serviceSettings,
                sweepInterval,
                export,
                purge,
                false);
    }

    /**
     * {@link AccountingStateMachine#STATE_VERSION}; {@code debug.state.version.supported} pretends another one, to test
     * rolling upgrades and activation (ADR 0005) — only with {@code debug.enabled=true}.
     */
    static int supportedStateVersion(Config config) {
        int version = config.integer("debug.state.version.supported", AccountingStateMachine.STATE_VERSION);
        if (version != AccountingStateMachine.STATE_VERSION && !config.bool("debug.enabled", false)) {
            throw new ConfigException(
                    "debug.state.version.supported: only allowed with debug.enabled=true (never in production)");
        }
        if (version < io.radiusward.cluster.service.StateVersions.BASELINE) {
            throw new ConfigException(
                    "debug.state.version.supported: at least " + io.radiusward.cluster.service.StateVersions.BASELINE);
        }
        return version;
    }

    public static final int INGRESS_OFFSET = 0;
    public static final int CONSENSUS_OFFSET = 1;
    public static final int LOG_OFFSET = 2;
    public static final int CATCHUP_OFFSET = 3;
    public static final int ARCHIVE_CONTROL_OFFSET = 4;
    public static final int ARCHIVE_REPLICATION_OFFSET = 5;
    public static final int PORTS_PER_NODE = 100;

    public static ClusterNodeConfig from(Config config) {
        int nodeId = config.integer("cluster.node.id");
        List<String> members = config.list("cluster.members", List.of("localhost", "localhost", "localhost"));
        if (nodeId < 0 || nodeId >= members.size()) {
            throw new ConfigException(
                    "cluster.node.id: " + nodeId + " is not an index into cluster.members " + members);
        }
        Profile profile = config.enumValue("profile", Profile.class, Profile.SMALL);
        File dataDir = new File(config.string("cluster.data.dir", ".local/data"), "node-" + nodeId);
        String aeronDir = config.string(
                "cluster.aeron.dir",
                new File(
                                System.getProperty("java.io.tmpdir"),
                                "radiusward-node-" + nodeId + "-"
                                        + Math.abs(dataDir.getAbsolutePath().hashCode()))
                        .getPath());
        int syncLevel = config.integer("archive.file.sync.level", 2);
        if (syncLevel < 0 || syncLevel > 2) {
            throw new ConfigException("archive.file.sync.level: expected 0, 1 or 2, got " + syncLevel);
        }
        AccountingStateMachine.Settings settings = new AccountingStateMachine.Settings(
                config.integer("service.max.sessions", profile.maxSessions()),
                config.duration("service.tombstone", Duration.ofHours(1)).toMillis(),
                config.duration("service.idle.timeout", Duration.ofHours(2)).toMillis(),
                config.duration("service.exact.key.window", Duration.ofMinutes(15))
                        .toMillis(),
                supportedStateVersion(config),
                config.integer(
                        "service.auth.reservations.max", AccountingStateMachine.Settings.DEFAULT_MAX_RESERVATIONS));
        return new ClusterNodeConfig(
                nodeId,
                members,
                config.integer("cluster.base.port", 9000),
                dataDir,
                aeronDir,
                profile,
                // 1.5 s: a crashed leader is replaced in ~2 s, below a typical 3 s NAS timeout (Phase 2 plan, P2.3)
                config.duration("cluster.leader.heartbeat.timeout", Duration.ofMillis(1500)),
                config.duration("cluster.election.timeout", Duration.ofMillis(500)),
                config.duration("cluster.session.timeout", Duration.ofSeconds(10)),
                config.duration("snapshot.interval", Duration.ofHours(1)),
                syncLevel,
                // below this the member reports not ready: a full disk ends in SIGBUS on a mapped file
                config.bytes("cluster.disk.min.free", 1L << 30),
                config.integer("cluster.client.sessions.max", 256),
                settings,
                config.duration("service.sweep.interval", Duration.ofSeconds(60)),
                ExportConfig.from(config),
                LogPurgeConfig.from(config),
                // keep newer state-machine versions off after an upgrade (rollback stays possible, ADR 0005)
                config.bool("cluster.version.hold", false));
    }

    public String host() {
        return members.get(nodeId);
    }

    public int port(int memberId, int offset) {
        return basePort + PORTS_PER_NODE * memberId + offset;
    }

    /** {@code id,ingress,consensus,log,catchup,archive|...} as Aeron Cluster expects. */
    public String clusterMembers() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < members.size(); i++) {
            String h = members.get(i);
            sb.append(i)
                    .append(',')
                    .append(h)
                    .append(':')
                    .append(port(i, INGRESS_OFFSET))
                    .append(',')
                    .append(h)
                    .append(':')
                    .append(port(i, CONSENSUS_OFFSET))
                    .append(',')
                    .append(h)
                    .append(':')
                    .append(port(i, LOG_OFFSET))
                    .append(',')
                    .append(h)
                    .append(':')
                    .append(port(i, CATCHUP_OFFSET))
                    .append(',')
                    .append(h)
                    .append(':')
                    .append(port(i, ARCHIVE_CONTROL_OFFSET));
            if (i < members.size() - 1) {
                sb.append('|');
            }
        }
        return sb.toString();
    }

    /** Client-side ingress endpoints {@code 0=host:port,1=...}. */
    public static String ingressEndpoints(List<String> members, int basePort) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < members.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(i)
                    .append('=')
                    .append(members.get(i))
                    .append(':')
                    .append(basePort + PORTS_PER_NODE * i + INGRESS_OFFSET);
        }
        return sb.toString();
    }
}
