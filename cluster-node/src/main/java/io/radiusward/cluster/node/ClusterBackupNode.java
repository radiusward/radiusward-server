/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.cluster.ClusterBackup;
import io.aeron.cluster.RecordingLog;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.common.management.Health;
import io.radiusward.common.management.JsonWriter;
import io.radiusward.common.management.JvmMetrics;
import io.radiusward.common.management.PrometheusWriter;
import java.io.File;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A continuous backup of the cluster outside it (ADR 0065): Aeron's {@link ClusterBackup} keeps the latest snapshot
 * and the live log of the members in its own data directory, in a member's layout, so {@link ClusterRestore} can make
 * any member — or all three after a lost quorum — from it. It is not a member: it takes no part in elections and the
 * cluster runs the same without it.
 */
public final class ClusterBackupNode implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(ClusterBackupNode.class);

    /**
     * Settings of the backup process.
     *
     * @param members the cluster members' hosts, as {@code cluster.members}
     * @param basePort the cluster's {@code cluster.base.port}
     * @param host the address the members reach the backup at
     * @param port the first of the backup's four ports: consensus, catch-up, archive control, archive replication
     * @param dataDir where the copy is kept, in a member's layout ({@code archive/}, {@code cluster/})
     * @param source the member the backup copies from
     * @param interval how often to look for a newer snapshot
     */
    public record Settings(
            List<String> members,
            int basePort,
            String host,
            int port,
            File dataDir,
            String aeronDir,
            ClusterBackup.SourceType source,
            Duration interval,
            int fileSyncLevel,
            int segmentLength) {

        public static Settings from(Config config) {
            String source = config.string("backup.source", "follower").toUpperCase(Locale.ROOT);
            ClusterBackup.SourceType type;
            try {
                type = ClusterBackup.SourceType.valueOf(source);
            } catch (IllegalArgumentException e) {
                throw new ConfigException("backup.source: follower, leader or any, not " + source);
            }
            return new Settings(
                    config.list("cluster.members", List.of("localhost", "localhost", "localhost")),
                    config.integer("cluster.base.port", 9000),
                    config.string("backup.host", "localhost"),
                    config.integer("backup.port", 9900),
                    new File(config.string("backup.data.dir", ".local/data/backup")),
                    config.string(
                            "backup.aeron.dir",
                            new File(System.getProperty("java.io.tmpdir"), "radiusward-backup").getPath()),
                    type,
                    config.duration("backup.interval", Duration.ofMinutes(30)),
                    config.integer("archive.file.sync.level", 2),
                    (int) config.bytes("archive.segment.length", 128L << 20));
        }

        String consensusEndpoints() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < members.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(members.get(i))
                        .append(':')
                        .append(basePort + ClusterNodeConfig.PORTS_PER_NODE * i + ClusterNodeConfig.CONSENSUS_OFFSET);
            }
            return sb.toString();
        }
    }

    private final Settings settings;
    private final BackupProcess process;

    private ClusterBackupNode(Settings settings, BackupProcess process) {
        this.settings = settings;
        this.process = process;
    }

    public static ClusterBackupNode launch(Settings s) {
        LOG.info("backing up cluster {} into {} (from a {})", s.consensusEndpoints(), s.dataDir(), s.source());
        BackupProcess process = BackupProcess.launch(
                s.dataDir(),
                s.aeronDir(),
                1_000_000, // an archive id apart from the members'
                new BackupProcess.Endpoints(s.host(), s.port(), s.port() + 1, s.port() + 2, s.port() + 3),
                s.consensusEndpoints(),
                s.source(),
                s.interval(),
                s.fileSyncLevel(),
                s.segmentLength(),
                t -> LOG.warn("backup: {}", t.toString()));
        return new ClusterBackupNode(s, process);
    }

    public ClusterBackup.State state() {
        return process.state();
    }

    /** Position of the cluster's log the backup has recorded; -1 before it records one. */
    public long liveLogPosition() {
        return process.liveLogPosition();
    }

    /** The latest snapshot the backup holds; {@code null} before the first. */
    public RecordingLog.Entry latestSnapshot() {
        return BackupProcess.latestSnapshot(process.clusterDir());
    }

    public File dataDir() {
        return settings.dataDir();
    }

    public Health health() {
        return Health.up("backup " + state());
    }

    /** Ready while it records the live log and holds a snapshot: a restore from it would work now. */
    public Health ready() {
        ClusterBackup.State state = state();
        if (state != ClusterBackup.State.BACKING_UP) {
            return Health.down("backup " + state);
        }
        RecordingLog.Entry snapshot = latestSnapshot();
        if (snapshot == null) {
            return Health.down("no snapshot yet: the cluster has not taken one");
        }
        return Health.up("backing up, snapshot at " + snapshot.logPosition + ", live log at " + liveLogPosition());
    }

    public String stateJson() {
        RecordingLog.Entry snapshot = latestSnapshot();
        return new JsonWriter()
                .field("component", "cluster-backup")
                .field("state", state().name())
                .field("liveLogPosition", liveLogPosition())
                .field("snapshotLogPosition", snapshot == null ? -1 : snapshot.logPosition)
                .field("snapshotTimestamp", snapshot == null ? -1 : snapshot.timestamp)
                .field("dataDir", settings.dataDir().getPath())
                .finish();
    }

    public String metrics() {
        PrometheusWriter w = new PrometheusWriter();
        ClusterBackup.State current = state();
        w.gauge("radiusward_backup_state", "1 for the state the cluster backup is in (BACKING_UP once it records)");
        for (ClusterBackup.State st : ClusterBackup.State.values()) {
            w.sample(st == current ? 1 : 0, "state", st.name().toLowerCase(Locale.ROOT));
        }
        w.gauge("radiusward_backup_live_log_position_bytes", "Position of the cluster's log the backup has recorded")
                .sample(liveLogPosition());
        RecordingLog.Entry snapshot = latestSnapshot();
        w.gauge("radiusward_backup_snapshot_log_position_bytes", "Log position of the latest snapshot in the backup")
                .sample(snapshot == null ? -1 : snapshot.logPosition);
        w.gauge("radiusward_backup_snapshot_timestamp_seconds", "When the latest snapshot in the backup was taken")
                .sample(snapshot == null ? 0 : snapshot.timestamp / 1000.0);
        w.counter("radiusward_log_messages_dropped_total", "Log messages dropped because the logging ring was full")
                .sample(io.radiusward.common.logging.NonBlockingQueueFullPolicy.dropped());
        JvmMetrics.write(w);
        return w.finish();
    }

    @Override
    public void close() {
        process.close();
        LOG.info("backup stopped");
    }
}
