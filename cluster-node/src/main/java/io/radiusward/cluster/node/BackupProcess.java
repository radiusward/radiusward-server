/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.archive.Archive;
import io.aeron.archive.ArchiveThreadingMode;
import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.ClusterBackup;
import io.aeron.cluster.ConsensusModule;
import io.aeron.cluster.RecordingLog;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import java.io.File;
import java.time.Duration;
import org.agrona.CloseHelper;
import org.agrona.ErrorHandler;

/**
 * A media driver, an archive and Aeron's {@link ClusterBackup} copying the latest snapshot and the live log of a
 * running cluster into {@code <dataDir>/archive} and {@code <dataDir>/cluster} — the layout of a member's data
 * directory. Used once to seed a replaced member ({@link ClusterSeed}, ADR 0063) and continuously by the backup
 * process ({@link ClusterBackupNode}, ADR 0065).
 */
final class BackupProcess implements AutoCloseable {

    static final String LOCAL_CONTROL = "aeron:ipc?term-length=64k";

    /**
     * Where the backup listens: its consensus responses, the catch-up of the live log and its archive's control and
     * replication, all on {@code host}.
     */
    record Endpoints(String host, int consensusPort, int catchupPort, int archiveControlPort, int replicationPort) {}

    private final MediaDriver driver;
    private final Archive archive;
    private final ClusterBackup backup;
    private final File clusterDir;
    private final String aeronDir;

    private BackupProcess(MediaDriver driver, Archive archive, ClusterBackup backup, File clusterDir, String aeronDir) {
        this.driver = driver;
        this.archive = archive;
        this.backup = backup;
        this.clusterDir = clusterDir;
        this.aeronDir = aeronDir;
    }

    /**
     * @param consensusEndpoints the members' consensus endpoints, {@code host:port,host:port}
     * @param source which member to copy from
     * @param interval how often to look for a newer snapshot once backing up
     */
    static BackupProcess launch(
            File dataDir,
            String aeronDir,
            int archiveId,
            Endpoints at,
            String consensusEndpoints,
            ClusterBackup.SourceType source,
            Duration interval,
            int fileSyncLevel,
            int segmentLength,
            ErrorHandler errorHandler) {
        File archiveDir = new File(dataDir, "archive");
        File clusterDir = new File(dataDir, "cluster");
        MediaDriver driver = null;
        Archive archive = null;
        try {
            driver = MediaDriver.launch(new MediaDriver.Context()
                    .aeronDirectoryName(aeronDir)
                    .threadingMode(ThreadingMode.SHARED)
                    .dirDeleteOnStart(true)
                    .dirDeleteOnShutdown(true)
                    .errorHandler(errorHandler));
            archive = Archive.launch(new Archive.Context()
                    .errorHandler(errorHandler)
                    .aeronDirectoryName(aeronDir)
                    .archiveDir(archiveDir)
                    .archiveId(archiveId)
                    .controlChannel("aeron:udp?endpoint=" + at.host() + ":" + at.archiveControlPort())
                    .localControlChannel(LOCAL_CONTROL)
                    .replicationChannel("aeron:udp?endpoint=" + at.host() + ":" + at.replicationPort())
                    .recordingEventsEnabled(false)
                    .threadingMode(ArchiveThreadingMode.SHARED)
                    .fileSyncLevel(fileSyncLevel)
                    .catalogFileSyncLevel(fileSyncLevel)
                    .segmentFileLength(segmentLength));
            ClusterBackup backup = ClusterBackup.launch(new ClusterBackup.Context()
                    .aeronDirectoryName(aeronDir)
                    .clusterDir(clusterDir)
                    .clusterConsensusEndpoints(consensusEndpoints)
                    .consensusChannel("aeron:udp?endpoint=" + at.host() + ":" + at.consensusPort())
                    .catchupEndpoint(at.host() + ":" + at.catchupPort())
                    .sourceType(source)
                    .clusterBackupIntervalNs(interval.toNanos())
                    .archiveContext(new AeronArchive.Context()
                            .aeronDirectoryName(aeronDir)
                            .controlRequestChannel(LOCAL_CONTROL)
                            .controlResponseChannel(LOCAL_CONTROL))
                    .clusterArchiveContext(new AeronArchive.Context()
                            .aeronDirectoryName(aeronDir)
                            .controlRequestChannel("aeron:udp") // the backup puts the member's archive endpoint in
                            .controlResponseChannel("aeron:udp?endpoint=" + at.host() + ":0"))
                    .clusterBackupResponseTimeoutNs(Duration.ofSeconds(2).toNanos())
                    .errorHandler(errorHandler)
                    .deleteDirOnStart(false));
            return new BackupProcess(driver, archive, backup, clusterDir, aeronDir);
        } catch (RuntimeException e) {
            CloseHelper.quietCloseAll(archive, driver);
            throw e;
        }
    }

    ClusterBackup.State state() {
        return ClusterBackup.State.get(backup.context().stateCounter());
    }

    /** Position of the live log the backup has recorded; -1 before it records one. */
    long liveLogPosition() {
        io.aeron.Counter counter = backup.context().liveLogPositionCounter();
        return counter == null || counter.isClosed() ? -1 : counter.get();
    }

    File clusterDir() {
        return clusterDir;
    }

    /** A client of the backup's own archive, for positions of its recordings. */
    AeronArchive connectLocal() {
        return AeronArchive.connect(new AeronArchive.Context()
                .aeronDirectoryName(aeronDir)
                .controlRequestChannel(LOCAL_CONTROL)
                .controlResponseChannel(LOCAL_CONTROL));
    }

    /** The latest consensus-module snapshot in the recording log; {@code null} if none. */
    static RecordingLog.Entry latestSnapshot(File clusterDir) {
        try (RecordingLog log = new RecordingLog(clusterDir, false)) {
            return log.getLatestSnapshot(ConsensusModule.Configuration.SERVICE_ID);
        } catch (RuntimeException e) {
            return null; // not written yet, or being written
        }
    }

    /** Whether the recorded log reaches the latest snapshot and the beginning of the last leadership term. */
    static boolean logReachesSnapshot(AeronArchive archive, File clusterDir) {
        try (RecordingLog log = new RecordingLog(clusterDir, false)) {
            RecordingLog.Entry snapshot = log.getLatestSnapshot(ConsensusModule.Configuration.SERVICE_ID);
            RecordingLog.Entry term = log.findLastTerm();
            if (snapshot == null || term == null) {
                return false;
            }
            long position = archive.getRecordingPosition(term.recordingId);
            if (position == AeronArchive.NULL_POSITION) {
                position = archive.getStopPosition(term.recordingId);
            }
            // a member joining the current term without an election needs the log up to where that term began
            return position >= Math.max(snapshot.logPosition, term.termBaseLogPosition);
        } catch (RuntimeException e) {
            return false; // the recording log is being written
        }
    }

    @Override
    public void close() {
        CloseHelper.quietCloseAll(backup, archive, driver);
    }
}
