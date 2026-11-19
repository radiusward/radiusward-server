/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.Aeron;
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
import io.radiusward.common.management.Health;
import io.radiusward.exporter.Exporter;
import io.radiusward.exporter.ExporterContext;
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

    static final long OWN_NAME_WAIT_MS = 60_000;
    private static final Logger LOG = LogManager.getLogger(ClusterNode.class);

    /**
     * The error handler of the member's own Aeron clients (log purge, version reports): logged. Aeron's default exits
     * the JVM when the media driver goes away, which the member's shutdown does.
     */
    static final org.agrona.ErrorHandler LOG_ERRORS = t -> LOG.warn("member Aeron client: {}", t.toString());

    private final ClusterNodeConfig config;
    private final AccountingService service;
    private final ClusteredMediaDriver clusteredMediaDriver;
    private final ClusteredServiceContainer container;
    private final ScheduledExecutorService scheduler;
    /** The archive's local control channel; the exporter replays the log through it. */
    static final String LOCAL_CONTROL_CHANNEL = "aeron:ipc?term-length=64k";

    private volatile boolean terminated;
    private final ClusterNodeProbes probes;
    private volatile Exporter exporter;
    private Aeron purgeAeron;
    private AeronArchive purgeArchive;
    private MemberReporter reporter;
    private volatile LogPurger.Result lastPurge;

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
        this.probes =
                new ClusterNodeProbes(config, service.stats(), this::electionState, () -> lastPurge, () -> exporter);
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
                .localControlChannel(LOCAL_CONTROL_CHANNEL)
                .replicationChannel("aeron:udp?endpoint=" + host + ":"
                        + config.port(id, ClusterNodeConfig.ARCHIVE_REPLICATION_OFFSET))
                .archiveClientContext(replicationClient)
                .recordingEventsEnabled(false)
                .threadingMode(profile == Profile.LARGE ? ArchiveThreadingMode.DEDICATED : ArchiveThreadingMode.SHARED)
                .fileSyncLevel(config.fileSyncLevel())
                .catalogFileSyncLevel(config.fileSyncLevel())
                .segmentFileLength(config.purge().segmentLength())
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
                // RADIUS servers, two lease clients per sink and a position reporter per member, admin tools
                .maxConcurrentSessions(config.maxClientSessions())
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
        awaitOwnAddress(config.host(), OWN_NAME_WAIT_MS);
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
        if (config.export().enabled()) {
            node.exporter = Exporter.start(
                    config.export().sinks(),
                    config.export().providers(),
                    new ExporterContext(
                            id,
                            config.aeronDir(),
                            new File(config.dataDir(), "cluster"),
                            ClusterNodeConfig.ingressEndpoints(config.members(), config.basePort()),
                            config.host(),
                            LOCAL_CONTROL_CHANNEL,
                            config.serviceSettings(),
                            config.export().pluginsDir(),
                            config.export().dictionaryDir()));
        }
        long interval = config.snapshotInterval().toMillis();
        if (interval > 0) {
            scheduler.scheduleAtFixedRate(node::snapshotIfLeader, interval, interval, TimeUnit.MILLISECONDS);
        }
        if (config.purge().enabled()) {
            long purgeMs = config.purge().interval().toMillis();
            scheduler.scheduleWithFixedDelay(node::purgeTick, purgeMs, purgeMs, TimeUnit.MILLISECONDS);
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

    /**
     * Every {@code log.purge.interval}: report how far this member's log reaches, then purge what nobody needs
     * any more (ADR 0014). Runs on the scheduler thread; failures are logged and retried next time.
     */
    void purgeTick() {
        try {
            File clusterDir = new File(config.dataDir(), "cluster");
            if (purgeArchive == null) {
                purgeAeron = Aeron.connect(new Aeron.Context()
                        .aeronDirectoryName(config.aeronDir())
                        .errorHandler(LOG_ERRORS));
                purgeArchive = AeronArchive.connect(new AeronArchive.Context()
                        .aeron(purgeAeron)
                        .controlRequestChannel(LOCAL_CONTROL_CHANNEL)
                        .controlRequestStreamId(AeronArchive.Configuration.localControlStreamId())
                        .controlResponseChannel(LOCAL_CONTROL_CHANNEL));
                reporter = new MemberReporter(
                        config.aeronDir(),
                        ClusterNodeConfig.ingressEndpoints(config.members(), config.basePort()),
                        config.host());
            }
            long logRecording;
            try (io.aeron.cluster.RecordingLog recordingLog = new io.aeron.cluster.RecordingLog(clusterDir, false)) {
                logRecording = recordingLog.findLastTermRecordingId();
            }
            if (logRecording >= 0) {
                long position = purgeArchive.getRecordingPosition(logRecording);
                if (position == AeronArchive.NULL_POSITION) {
                    position = purgeArchive.getStopPosition(logRecording);
                }
                reporter.report(
                        config.nodeId(),
                        position,
                        config.serviceSettings().supportedVersion(),
                        config.members().size(),
                        config.versionHold());
            }
            lastPurge = new LogPurger(
                            clusterDir, config.members().size(), config.purge().dryRun())
                    .purge(purgeArchive, service.stats());
        } catch (RuntimeException e) {
            LOG.warn("cluster node {}: log purge tick failed: {}", config.nodeId(), e.toString());
            closePurgeClients();
        }
    }

    private void closePurgeClients() {
        CloseHelper.quietCloseAll(reporter, purgeArchive, purgeAeron);
        reporter = null;
        purgeArchive = null;
        purgeAeron = null;
    }

    /** The consensus module's election state; {@code null} if it cannot be read. */
    io.aeron.cluster.ElectionState electionState() {
        try {
            io.aeron.Counter counter =
                    clusteredMediaDriver.consensusModule().context().electionStateCounter();
            return counter == null || counter.isClosed() ? null : io.aeron.cluster.ElectionState.get(counter);
        } catch (RuntimeException e) {
            return null;
        }
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

    /**
     * Waits until {@code host} resolves to an address of this machine (ADR 0062). On Kubernetes a member's pod can
     * start before its DNS record carries the pod's new address; Aeron would fail to bind its own endpoints and the
     * member would crash into back-off. Gives up after {@code waitMillis} and lets Aeron report the problem.
     */
    static boolean awaitOwnAddress(String host, long waitMillis) {
        long deadline = System.currentTimeMillis() + waitMillis;
        boolean warned = false;
        while (true) {
            String seen;
            try {
                java.net.InetAddress address = java.net.InetAddress.getByName(host);
                if (address.isAnyLocalAddress()
                        || address.isLoopbackAddress()
                        || java.net.NetworkInterface.getByInetAddress(address) != null) {
                    if (warned) {
                        LOG.info("{} resolves to this member's address {}", host, address.getHostAddress());
                    }
                    return true;
                }
                seen = "resolves to " + address.getHostAddress() + ", not an address of this member";
            } catch (java.io.IOException e) {
                seen = "does not resolve";
            }
            if (System.currentTimeMillis() >= deadline) {
                LOG.warn("{} {} after {} ms; starting anyway", host, seen, waitMillis);
                return false;
            }
            if (!warned) {
                LOG.warn("{} {} yet; waiting up to {} ms (a new pod's DNS record)", host, seen, waitMillis);
                warned = true;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /**
     * Ready when the service has started, a leader is known, the election is closed — a restarted member has caught
     * up with the leader by then (ADR 0062) — and the data directory has space left.
     */
    public Health ready() {
        return probes.ready();
    }

    /** {@code /state}: this member's view of the cluster, its log, its exporter. */
    public String stateJson() {
        return probes.stateJson();
    }

    /** {@code /metrics} in the Prometheus text format (metric list in docs/operations/monitoring.md). */
    public String metrics() {
        return probes.metrics();
    }

    void markTerminated() {
        terminated = true;
    }

    @Override
    public void close() {
        terminated = true;
        scheduler.shutdown(); // let a running snapshot request or purge tick finish: Aeron dislikes interrupts
        try {
            if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        closePurgeClients();
        if (exporter != null) {
            exporter.close();
        }
        CloseHelper.closeAll(container, clusteredMediaDriver);
        LOG.info("cluster node {} stopped", config.nodeId());
    }
}
