/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.archive.Archive;
import io.aeron.archive.ArchiveThreadingMode;
import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.ClusterBackup;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.stream.Stream;
import org.agrona.CloseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Seeds an empty member from the running cluster before it starts (ADR 0063). A member whose volume was lost cannot
 * catch up once the others purged their log below their snapshots; Aeron's {@link ClusterBackup} copies the latest
 * snapshot and the log after it from another member into this member's archive and cluster directories, and the member
 * then starts from them and catches up the rest like after a restart. The member's own ports are free until it starts,
 * so the backup uses them. When no other member answers within the timeout — a new cluster starting for the first
 * time — the partial directories are removed and the member starts empty.
 */
public final class ClusterSeed {

    private static final Logger LOG = LogManager.getLogger(ClusterSeed.class);
    private static final String LOCAL_CONTROL = "aeron:ipc?term-length=64k";

    private ClusterSeed() {}

    /** Whether this member has no cluster state yet (no recording log). */
    public static boolean empty(ClusterNodeConfig config) {
        return !new File(new File(config.dataDir(), "cluster"), "recording.log").exists();
    }

    /**
     * Seeds the member's data directory from the other members if it is empty.
     *
     * @return whether it was seeded; {@code false} if it was not empty or no member answered in time
     */
    public static boolean seedIfEmpty(ClusterNodeConfig config, Duration timeout) {
        if (!empty(config)) {
            return false;
        }
        LOG.info(
                "member {} has no cluster state: seeding it from the other members (up to {})",
                config.nodeId(),
                timeout);
        long start = System.nanoTime();
        State reached = run(config, timeout);
        if (reached == State.SEEDED && !hasSnapshot(config)) {
            // the cluster has not taken a snapshot yet, so nothing was purged either: the member catches up from the
            // others' logs, which a copy of only the live log would prevent
            LOG.info("member {}: the cluster has no snapshot yet, catching up from the log instead", config.nodeId());
            deleteState(config);
            return false;
        }
        if (reached == State.SEEDED) {
            LOG.info("member {} seeded in {} ms", config.nodeId(), (System.nanoTime() - start) / 1_000_000);
            return true;
        }
        LOG.warn(
                "member {} not seeded ({}): starting empty — right for a new cluster, a gap for a replaced member",
                config.nodeId(),
                reached == State.NO_ANSWER ? "no other member answered" : "the copy did not finish");
        deleteState(config);
        return false;
    }

    enum State {
        SEEDED,
        NO_ANSWER,
        INCOMPLETE
    }

    private static State run(ClusterNodeConfig config, Duration timeout) {
        String host = config.host();
        int id = config.nodeId();
        File archiveDir = new File(config.dataDir(), "archive");
        File clusterDir = new File(config.dataDir(), "cluster");
        String aeronDir = config.aeronDir() + "-seed";
        MediaDriver driver = null;
        Archive archive = null;
        ClusterBackup backup = null;
        try {
            driver = MediaDriver.launch(new MediaDriver.Context()
                    .aeronDirectoryName(aeronDir)
                    .threadingMode(ThreadingMode.SHARED)
                    .dirDeleteOnStart(true)
                    .dirDeleteOnShutdown(true));
            archive = Archive.launch(new Archive.Context()
                    .errorHandler(t -> LOG.warn("seeding member {} (archive): {}", id, t.toString()))
                    .aeronDirectoryName(aeronDir)
                    .archiveDir(archiveDir)
                    .archiveId(id)
                    .controlChannel("aeron:udp?endpoint=" + host + ":"
                            + config.port(id, ClusterNodeConfig.ARCHIVE_CONTROL_OFFSET))
                    .localControlChannel(LOCAL_CONTROL)
                    .replicationChannel("aeron:udp?endpoint=" + host + ":"
                            + config.port(id, ClusterNodeConfig.ARCHIVE_REPLICATION_OFFSET))
                    .recordingEventsEnabled(false)
                    .threadingMode(ArchiveThreadingMode.SHARED)
                    .fileSyncLevel(config.fileSyncLevel())
                    .catalogFileSyncLevel(config.fileSyncLevel())
                    .segmentFileLength(config.purge().segmentLength()));
            backup = ClusterBackup.launch(new ClusterBackup.Context()
                    .aeronDirectoryName(aeronDir)
                    .clusterDir(clusterDir)
                    .clusterConsensusEndpoints(otherConsensusEndpoints(config))
                    .consensusChannel(
                            "aeron:udp?endpoint=" + host + ":" + config.port(id, ClusterNodeConfig.CONSENSUS_OFFSET))
                    .catchupEndpoint(host + ":" + config.port(id, ClusterNodeConfig.CATCHUP_OFFSET))
                    .sourceType(ClusterBackup.SourceType.ANY)
                    .archiveContext(new AeronArchive.Context()
                            .aeronDirectoryName(aeronDir)
                            .controlRequestChannel(LOCAL_CONTROL)
                            .controlResponseChannel(LOCAL_CONTROL))
                    .clusterArchiveContext(new AeronArchive.Context()
                            .aeronDirectoryName(aeronDir)
                            .controlRequestChannel("aeron:udp") // the backup puts the member's archive endpoint in
                            .controlResponseChannel("aeron:udp?endpoint=" + host + ":0"))
                    .clusterBackupResponseTimeoutNs(Duration.ofSeconds(2).toNanos())
                    .errorHandler(t -> LOG.warn("seeding member {}: {}", id, t.toString()))
                    .deleteDirOnStart(false));
            return await(backup, clusterDir, aeronDir, timeout);
        } catch (RuntimeException e) {
            LOG.warn("seeding member {} failed: {}", id, e.toString());
            return State.INCOMPLETE;
        } finally {
            CloseHelper.quietCloseAll(backup, archive, driver);
        }
    }

    /**
     * Waits until the backup records the live log and its log recording reaches both the latest snapshot it retrieved
     * and the beginning of the current leadership term: a member can only extend a contiguous log recording and joins
     * the current term without an election (measured on Kubernetes and in ClusterSeedIT: closing the backup as soon as
     * it reported {@code BACKING_UP} left the recording megabytes short).
     */
    private static State await(ClusterBackup backup, File clusterDir, String aeronDir, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean answered = false;
        try (AeronArchive local = AeronArchive.connect(new AeronArchive.Context()
                .aeronDirectoryName(aeronDir)
                .controlRequestChannel(LOCAL_CONTROL)
                .controlResponseChannel(LOCAL_CONTROL))) {
            while (System.nanoTime() < deadline) {
                ClusterBackup.State state =
                        ClusterBackup.State.get(backup.context().stateCounter());
                if (state != ClusterBackup.State.BACKUP_QUERY && state != ClusterBackup.State.RESET_BACKUP) {
                    answered = true;
                }
                if (state == ClusterBackup.State.BACKING_UP
                        && (!hasSnapshot(clusterDir) || logReachesSnapshot(local, clusterDir))) {
                    return State.SEEDED; // without a snapshot the caller discards the copy at once
                }
                sleep(100);
            }
        }
        return answered ? State.INCOMPLETE : State.NO_ANSWER;
    }

    /** Whether the recorded log reaches the latest snapshot and the beginning of the last leadership term. */
    static boolean logReachesSnapshot(AeronArchive archive, File clusterDir) {
        try (io.aeron.cluster.RecordingLog log = new io.aeron.cluster.RecordingLog(clusterDir, false)) {
            io.aeron.cluster.RecordingLog.Entry snapshot =
                    log.getLatestSnapshot(io.aeron.cluster.ConsensusModule.Configuration.SERVICE_ID);
            io.aeron.cluster.RecordingLog.Entry term = log.findLastTerm();
            if (snapshot == null || term == null) {
                return false;
            }
            long position = archive.getRecordingPosition(term.recordingId);
            if (position == io.aeron.archive.client.AeronArchive.NULL_POSITION) {
                position = archive.getStopPosition(term.recordingId);
            }
            // a member joining the current term without an election needs the log up to where that term began
            return position >= Math.max(snapshot.logPosition, term.termBaseLogPosition);
        } catch (RuntimeException e) {
            return false; // the recording log is being written
        }
    }

    /** Whether the seeded recording log holds a snapshot of the consensus module. */
    static boolean hasSnapshot(ClusterNodeConfig config) {
        return hasSnapshot(new File(config.dataDir(), "cluster"));
    }

    static boolean hasSnapshot(File clusterDir) {
        try (io.aeron.cluster.RecordingLog log = new io.aeron.cluster.RecordingLog(clusterDir, false)) {
            return log.getLatestSnapshot(io.aeron.cluster.ConsensusModule.Configuration.SERVICE_ID) != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    static String otherConsensusEndpoints(ClusterNodeConfig config) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < config.members().size(); i++) {
            if (i == config.nodeId()) {
                continue;
            }
            if (!sb.isEmpty()) {
                sb.append(',');
            }
            sb.append(config.members().get(i)).append(':').append(config.port(i, ClusterNodeConfig.CONSENSUS_OFFSET));
        }
        return sb.toString();
    }

    private static void deleteState(ClusterNodeConfig config) {
        for (String dir : new String[] {"archive", "cluster"}) {
            Path p = new File(config.dataDir(), dir).toPath();
            if (!Files.exists(p)) {
                continue;
            }
            try (Stream<Path> files = Files.walk(p)) {
                files.sorted(Comparator.reverseOrder()).forEach(f -> f.toFile().delete());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while seeding", e);
        }
    }
}
