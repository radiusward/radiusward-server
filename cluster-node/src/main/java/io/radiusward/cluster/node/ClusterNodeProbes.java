/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.radiusward.cluster.service.ServiceStats;
import io.radiusward.common.logging.NonBlockingQueueFullPolicy;
import io.radiusward.common.management.Health;
import io.radiusward.common.management.JsonWriter;
import io.radiusward.common.management.JvmMetrics;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.exporter.Exporter;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * What a member's management server shows (ADR 0062): whether it is ready, {@code /state} and {@code /metrics}, from
 * the service's counters, the consensus module's election state, the last log purge and the exporter. Called by the
 * management server's threads; everything it reads is safe to read from them.
 */
final class ClusterNodeProbes {

    private static final Logger LOG = LogManager.getLogger(ClusterNode.class);

    private final ClusterNodeConfig config;
    private final ServiceStats stats;
    private final Supplier<io.aeron.cluster.ElectionState> election;
    private final Supplier<LogPurger.Result> lastPurge;
    private final Supplier<Exporter> exporter;
    private volatile boolean lowDisk;

    ClusterNodeProbes(
            ClusterNodeConfig config,
            ServiceStats stats,
            Supplier<io.aeron.cluster.ElectionState> election,
            Supplier<LogPurger.Result> lastPurge,
            Supplier<Exporter> exporter) {
        this.config = config;
        this.stats = stats;
        this.election = election;
        this.lastPurge = lastPurge;
        this.exporter = exporter;
    }

    /** See {@link ClusterNode#ready()}. */
    Health ready() {
        ServiceStats s = stats;
        if (s.fatal() != null) {
            return Health.down(s.fatal());
        }
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
        io.aeron.cluster.ElectionState election = this.election.get();
        if (election == null) { // the consensus module's counters are not readable: what the service saw
            return s.leaderMemberId() < 0
                    ? Health.down("no leader")
                    : Health.up(s.role() + ", leader " + s.leaderMemberId());
        }
        if (election != io.aeron.cluster.ElectionState.CLOSED) {
            return Health.down("election in progress: " + election);
        }
        // a closed election means a leader; the service names it only once it has seen the term begin in the log,
        // which a member started from a later snapshot (restarted or seeded, ADR 0063) does not until the next term
        return Health.up(s.role()
                + (s.leaderMemberId() < 0 ? ", leader known to the cluster" : ", leader " + s.leaderMemberId()));
    }

    String stateJson() {
        ServiceStats s = stats;
        JsonWriter json = new JsonWriter()
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
                .field("identityMismatches", s.identityMismatches())
                .field("stateVersionActive", s.activeVersion())
                .field("stateVersionSupported", config.serviceSettings().supportedVersion())
                .field("stateVersionLowestSupported", s.lowestSupportedVersion())
                .object("log")
                .field("dropped", NonBlockingQueueFullPolicy.dropped())
                .end();
        LogPurger.Result purge = lastPurge.get();
        if (purge != null) {
            json.object("logPurge")
                    .field("floor", purge.floor())
                    .field("logStart", purge.newStart())
                    .field("boundedBy", purge.reason())
                    .end();
        }
        Exporter e = exporter.get();
        if (e != null) {
            e.writeState(json, s.lastPosition());
        }
        return json.finish();
    }

    String metrics() {
        ServiceStats s = stats;
        String member = Integer.toString(config.nodeId());
        PrometheusWriter w = new PrometheusWriter();
        w.gauge("radiusward_cluster_leader", "1 on the leader")
                .sample("LEADER".equals(s.role()) ? 1 : 0, "member", member);
        w.gauge("radiusward_cluster_leader_member", "Member id of the current leader, -1 while unknown")
                .sample(s.leaderMemberId(), "member", member);
        w.counter("radiusward_cluster_leadership_terms_total", "Leadership term id (increases with every election)")
                .sample(Math.max(0, s.term()), "member", member);
        w.gauge("radiusward_cluster_log_position_bytes", "Log position of the last accounting entry applied")
                .sample(s.lastPosition(), "member", member);
        w.counter("radiusward_accounting_events_total", "Accounting events by outcome")
                .sample(s.applied(), "member", member, "outcome", "applied")
                .sample(s.duplicates(), "member", member, "outcome", "duplicate")
                .sample(s.stale(), "member", member, "outcome", "stale")
                .sample(s.rejected(), "member", member, "outcome", "rejected");
        w.counter(
                        "radiusward_accounting_export_lag_rejections_total",
                        "Accounting not acknowledged because a required sink was over its maxLag")
                .sample(s.exportLagRejections(), "member", member);
        w.counter(
                        "radiusward_nas_identity_mismatches_total",
                        "Accounting from gateways whose nas.<name>.identity differs from the entry's first one seen")
                .sample(s.identityMismatches(), "member", member);
        w.gauge("radiusward_state_version", "State-machine version (ADR 0005): active in the cluster, supported here")
                .sample(s.activeVersion(), "member", member, "kind", "active")
                .sample(config.serviceSettings().supportedVersion(), "member", member, "kind", "supported")
                .sample(s.lowestSupportedVersion(), "member", member, "kind", "lowest_supported");
        w.gauge("radiusward_state_version_held", "1 while cluster.version.hold keeps a supported version off")
                .sample(s.versionHeld() ? 1 : 0, "member", member);
        w.gauge("radiusward_sessions", "Sessions in the replicated state")
                .sample(s.activeSessions(), "member", member, "state", "active")
                .sample(s.stoppedSessions(), "member", member, "state", "stopped");
        w.counter("radiusward_snapshots_total", "Snapshots taken").sample(s.snapshots(), "member", member);
        w.counter("radiusward_egress_dropped_total", "Replies to gateways given up under back pressure")
                .sample(s.egressDropped(), "member", member);
        w.gauge("radiusward_disk_free_bytes", "Usable space in the data directory")
                .sample(config.dataDir().getUsableSpace(), "member", member);
        w.gauge("radiusward_disk_min_free_bytes", "cluster.disk.min.free")
                .sample(config.diskMinFree(), "member", member);
        LogPurger.Result purge = lastPurge.get();
        if (purge != null) {
            w.gauge("radiusward_log_start_bytes", "Lowest log position still on this member's disk")
                    .sample(purge.newStart(), "member", member);
            w.gauge("radiusward_log_purge_floor_bytes", "Position below which nobody needs the log any more")
                    .sample(purge.floor(), "member", member);
        }
        w.counter("radiusward_log_messages_dropped_total", "Log messages dropped because the logging ring was full")
                .sample(NonBlockingQueueFullPolicy.dropped());
        Exporter e = exporter.get();
        if (e != null) {
            e.writeMetrics(w, member, s.lastPosition(), System.currentTimeMillis());
        }
        JvmMetrics.write(w);
        return w.finish();
    }
}
