/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.archive.Archive;
import io.aeron.archive.ArchiveThreadingMode;
import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.ClusterControl;
import io.aeron.cluster.ClusteredMediaDriver;
import io.aeron.cluster.ConsensusModule;
import io.aeron.cluster.service.ClusteredServiceContainer;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.radiusward.cluster.service.AccountingService;
import io.radiusward.cluster.service.ServiceStats;
import io.radiusward.common.Profile;
import io.radiusward.common.logging.NonBlockingQueueFullPolicy;
import io.radiusward.common.management.Health;
import io.radiusward.common.management.JsonWriter;
import java.io.File;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.agrona.CloseHelper;
import org.agrona.ErrorHandler;
import org.agrona.concurrent.status.AtomicCounter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * One running cluster member: media driver, archive (fsync per {@code archive.file.sync.level}), consensus
 * module and the {@link AccountingService}, plus the hourly snapshot trigger.
 */
public final class ClusterNode implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(ClusterNode.class);

    private final ClusterNodeConfig config;
    private final AccountingService service;
    private final ClusteredMediaDriver clusteredMediaDriver;
    private final ClusteredServiceContainer container;
    private final ScheduledExecutorService scheduler;
    private volatile boolean terminated;
    private volatile boolean lowDisk;

    private ClusterNode(
            ClusterNodeConfig config,
            AccountingService service,
            ClusteredMediaDriver clusteredMediaDriver,
            ClusteredServiceContainer container,
            ScheduledExecutorService scheduler) {
        this.config = config;
        this.service = service;
        this.clusteredMediaDriver = clusteredMediaDriver;
        this.container = container;
        this.scheduler = scheduler;
    }

    private static Launched launchOnce(ClusterNodeConfig config, Runnable terminationHook) {
        String host = config.host();
        int id = config.nodeId();
        Profile profile = config.profile();
        ErrorHandler errorHandler = throwable -> {
            if (throwable instanceof io.aeron.exceptions.AeronEvent) {
                LOG.warn("cluster node {}: {}", id, throwable.getMessage()); // e.g. log recording stopped on failover
            } else {
                LOG.error("cluster node {} error", id, throwable);
            }
        };
        File archiveDir = new File(config.dataDir(), "archive");
        File clusterDir = new File(config.dataDir(), "cluster");

        MediaDriver.Context driver = new MediaDriver.Context()
                .aeronDirectoryName(config.aeronDir())
                .threadingMode(ThreadingMode.valueOf(profile.threadingMode()))
                .publicationTermBufferLength(profile.termLength())
                .ipcTermBufferLength(profile.ipcTermLength())
                .dirDeleteOnStart(true)
                .dirDeleteOnShutdown(true)
                .errorHandler(errorHandler);

        AeronArchive.Context replicationClient =
                new AeronArchive.Context().controlResponseChannel("aeron:udp?endpoint=" + host + ":0");
        Archive.Context archive = new Archive.Context()
                .aeronDirectoryName(config.aeronDir())
                .archiveDir(archiveDir)
                .archiveId(id)
                .controlChannel(
                        "aeron:udp?endpoint=" + host + ":" + config.port(id, ClusterNodeConfig.ARCHIVE_CONTROL_OFFSET))
                .localControlChannel("aeron:ipc?term-length=64k")
                .replicationChannel("aeron:udp?endpoint=" + host + ":"
                        + config.port(id, ClusterNodeConfig.ARCHIVE_REPLICATION_OFFSET))
                .archiveClientContext(replicationClient)
                .recordingEventsEnabled(false)
                .threadingMode(profile == Profile.LARGE ? ArchiveThreadingMode.DEDICATED : ArchiveThreadingMode.SHARED)
                .fileSyncLevel(config.fileSyncLevel())
                .catalogFileSyncLevel(config.fileSyncLevel())
                .errorHandler(errorHandler);

        AeronArchive.Context archiveClient = new AeronArchive.Context()
                .controlRequestChannel(archive.localControlChannel())
                .controlRequestStreamId(archive.localControlStreamId())
                .controlResponseChannel(archive.localControlChannel())
                .aeronDirectoryName(config.aeronDir());

        ConsensusModule.Context consensus = new ConsensusModule.Context()
                .clusterMemberId(id)
                .clusterMembers(config.clusterMembers())
                .clusterDir(clusterDir)
                // recording log and node state: without this they are never fsynced and a power loss can
                // leave them empty, so the member cannot start again (found by PowerLossIT)
                .fileSyncLevel(config.fileSyncLevel())
                .archiveContext(archiveClient.clone())
                .serviceCount(1)
                .ingressChannel("aeron:udp")
                .logChannel("aeron:udp?" + profile.termLengthParam())
                .replicationChannel("aeron:udp?endpoint=" + host + ":0")
                .leaderHeartbeatTimeoutNs(config.leaderHeartbeatTimeout().toNanos())
                .electionTimeoutNs(config.electionTimeout().toNanos())
                .sessionTimeoutNs(config.sessionTimeout().toNanos())
                .errorHandler(errorHandler);

        AccountingService service = new AccountingService(
                config.serviceSettings(), config.sweepInterval().toMillis());
        ClusteredServiceContainer.Context serviceContext = new ClusteredServiceContainer.Context()
                .aeronDirectoryName(config.aeronDir())
                .archiveContext(archiveClient.clone())
                .clusterDir(clusterDir)
                .clusteredService(service)
                .serviceId(0)
                .errorHandler(errorHandler);

        if (terminationHook != null) {
            driver.terminationHook(terminationHook);
            consensus.terminationHook(terminationHook);
            serviceContext.terminationHook(terminationHook);
        }

        ClusteredMediaDriver clusteredMediaDriver = null;
        ClusteredServiceContainer container = null;
        try {
            clusteredMediaDriver = ClusteredMediaDriver.launch(driver, archive, consensus);
            container = ClusteredServiceContainer.launch(serviceContext);
        } catch (RuntimeException e) {
            CloseHelper.quietCloseAll(container, clusteredMediaDriver);
            throw e;
        }
        return new Launched(service, clusteredMediaDriver, container);
    }

    private record Launched(
            AccountingService service,
            ClusteredMediaDriver clusteredMediaDriver,
            ClusteredServiceContainer container) {}

    /** How long to keep retrying while a crashed predecessor's mark file still looks alive. */
    private static final long MARK_FILE_WAIT_MS = 20_000;

    /** Launches the member and returns once its components are running (not necessarily elected). */
    public static ClusterNode launch(ClusterNodeConfig config, Runnable terminationHook) {
        long deadline = System.currentTimeMillis() + MARK_FILE_WAIT_MS;
        Launched launched;
        while (true) {
            try {
                launched = launchOnce(config, terminationHook);
                break;
            } catch (IllegalStateException e) {
                // Aeron refuses mark files updated within the last 10 s; after kill -9 that is the dead process.
                // A live second instance keeps refreshing its mark file, so it is still refused after the wait.
                if (!String.valueOf(e.getMessage()).contains("active mark file detected")
                        || System.currentTimeMillis() > deadline) {
                    throw e;
                }
                LOG.warn("mark file of a previous instance is still fresh ({}); retrying", e.getMessage());
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
        AccountingService service = launched.service();
        ClusteredMediaDriver clusteredMediaDriver = launched.clusteredMediaDriver();
        ClusteredServiceContainer container = launched.container();
        int id = config.nodeId();
        Profile profile = config.profile();

        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "snapshot-scheduler-" + id);
            t.setDaemon(true);
            return t;
        });
        ClusterNode node = new ClusterNode(config, service, clusteredMediaDriver, container, scheduler);
        long interval = config.snapshotInterval().toMillis();
        if (interval > 0) {
            scheduler.scheduleAtFixedRate(node::snapshotIfLeader, interval, interval, TimeUnit.MILLISECONDS);
        }
        LOG.info(
                "cluster node {} started on {} (members {}, profile {}, fsync level {})",
                id,
                config.host(),
                config.clusterMembers(),
                profile,
                config.fileSyncLevel());
        return node;
    }

    /** Requests a snapshot when this member is the leader; followers take theirs as part of it. */
    void snapshotIfLeader() {
        try {
            if ("LEADER".equals(service.stats().role())) {
                requestSnapshot();
            }
        } catch (RuntimeException e) {
            LOG.warn("snapshot request failed", e);
        }
    }

    /** Toggles the cluster's snapshot control (same as {@code ClusterTool snapshot}); true if accepted. */
    public boolean requestSnapshot() {
        ConsensusModule.Context ctx = clusteredMediaDriver.consensusModule().context();
        AtomicCounter toggle = ClusterControl.findControlToggle(ctx.aeron().countersReader(), ctx.clusterId());
        if (toggle == null) {
            return false;
        }
        boolean accepted = ClusterControl.ToggleState.SNAPSHOT.toggle(toggle);
        if (accepted) {
            LOG.info("snapshot requested");
        }
        return accepted;
    }

    public ServiceStats stats() {
        return service.stats();
    }

    public ClusterNodeConfig config() {
        return config;
    }

    public Health health() {
        return terminated ? Health.down("terminated") : Health.up("cluster node " + config.nodeId() + " running");
    }

    /** Ready when the service has started, a leader is known and the data directory has space left. */
    public Health ready() {
        ServiceStats s = service.stats();
        if (!s.started()) {
            return Health.down("service not started");
        }
        long free = config.dataDir().getUsableSpace();
        boolean low = config.diskMinFree() > 0 && free < config.diskMinFree();
        if (low != lowDisk) {
            lowDisk = low;
            if (low) {
                LOG.warn(
                        "low disk space in {}: {} MiB free, cluster.disk.min.free {} MiB; a full disk stops this member",
                        config.dataDir(),
                        free >> 20,
                        config.diskMinFree() >> 20);
            } else {
                LOG.info("disk space in {} back to {} MiB free", config.dataDir(), free >> 20);
            }
        }
        if (low) {
            return Health.down(
                    "low disk space: " + (free >> 20) + " MiB free, need " + (config.diskMinFree() >> 20) + " MiB");
        }
        if (s.leaderMemberId() < 0) {
            return Health.down("no leader");
        }
        return Health.up(s.role() + ", leader " + s.leaderMemberId());
    }

    public String stateJson() {
        ServiceStats s = service.stats();
        return new JsonWriter()
                .field("component", "cluster-node")
                .field("nodeId", config.nodeId())
                .field("role", s.role())
                .field("leaderId", s.leaderMemberId())
                .field("term", s.term())
                .field("logPosition", s.lastPosition())
                .field("applied", s.applied())
                .field("duplicates", s.duplicates())
                .field("stale", s.stale())
                .field("rejected", s.rejected())
                .field("activeSessions", s.activeSessions())
                .field("stoppedSessions", s.stoppedSessions())
                .field("stateDigest", Long.toHexString(s.digest()))
                .field("diskFreeBytes", config.dataDir().getUsableSpace())
                .field("snapshots", s.snapshots())
                .field("egressDropped", s.egressDropped())
                .object("log")
                .field("dropped", NonBlockingQueueFullPolicy.dropped())
                .end()
                .finish();
    }

    void markTerminated() {
        terminated = true;
    }

    @Override
    public void close() {
        terminated = true;
        scheduler.shutdownNow();
        CloseHelper.closeAll(container, clusteredMediaDriver);
        LOG.info("cluster node {} stopped", config.nodeId());
    }
}
