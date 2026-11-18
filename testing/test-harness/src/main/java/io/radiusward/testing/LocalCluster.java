/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.node.ClusterNodeConfig;
import io.radiusward.cluster.node.LogPurgeConfig;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.common.Profile;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.server.AccessHandler;
import io.radiusward.server.AuthConfig;
import io.radiusward.server.CoaConfig;
import io.radiusward.server.NasClient;
import io.radiusward.server.NasRegistry;
import io.radiusward.server.ProxyConfig;
import io.radiusward.server.RadiusServer;
import io.radiusward.server.RadsecConfig;
import io.radiusward.server.ServerConfig;
import io.radiusward.tools.admin.AdminClient;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;
import org.agrona.CloseHelper;

/**
 * A complete radiusward cluster in one JVM: cluster members and gateways on loopback with their own
 * directories and free ports. Used by integration tests and {@link DevCluster}. Real Aeron, real UDP, real
 * fsync; only {@code kill -9} cannot be simulated here (see the e2e tests).
 */
public final class LocalCluster implements AutoCloseable {

    public static final String SECRET = "testing123";
    public static final String NAS_NAME = "local";
    public static final int NAS_ID = 1001;

    private final File baseDir;
    private final int basePort;
    private final int memberCount;
    private final ClusterNode[] nodes;
    private final List<RadiusServer> radiusServers = new ArrayList<>();
    private final Duration snapshotInterval;
    private java.util.function.IntFunction<ExportConfig> export = id -> ExportConfig.NONE;
    private LogPurgeConfig purge = LogPurgeConfig.DEFAULTS;
    private AccountingStateMachine.Settings settings =
            AccountingStateMachine.Settings.defaults(Profile.SMALL.maxSessions());
    private Duration sweepInterval = Duration.ofSeconds(60);

    /** Purge settings for members started from now on (tests use small segments and short intervals). */
    public LocalCluster purge(LogPurgeConfig purge) {
        this.purge = purge;
        return this;
    }

    private LocalCluster(File baseDir, int basePort, int memberCount, Duration snapshotInterval) {
        this.baseDir = baseDir;
        this.basePort = basePort;
        this.memberCount = memberCount;
        this.nodes = new ClusterNode[memberCount];
        this.snapshotInterval = snapshotInterval;
    }

    /** Starts {@code members} cluster nodes and {@code gatewayCount} gateways (RADIUS ports chosen freely). */
    public static LocalCluster start(File baseDir, int members, int serverCount) {
        return builder(baseDir).members(members).radiusServers(serverCount).start();
    }

    /** A cluster with other settings: {@code LocalCluster.builder(dir).members(3).gateways(2).export(..).start()}. */
    public static Builder builder(File baseDir) {
        return new Builder(baseDir);
    }

    /** What to start; every setting has the default {@link #start(File, int, int)} uses. */
    public static final class Builder {
        private final File baseDir;
        private int members = 3;
        private int radiusServers;
        private int basePort = -1;
        private int[] radiusPorts;
        private Duration snapshotInterval = Duration.ZERO;
        private java.util.function.IntFunction<ExportConfig> export = id -> ExportConfig.NONE;
        private LogPurgeConfig purge = LogPurgeConfig.DEFAULTS;
        private AccountingStateMachine.Settings settings =
                AccountingStateMachine.Settings.defaults(Profile.SMALL.maxSessions());
        private Duration sweepInterval = Duration.ofSeconds(60);

        private Builder(File baseDir) {
            this.baseDir = baseDir;
        }

        public Builder members(int members) {
            this.members = members;
            return this;
        }

        public Builder radiusServers(int radiusServers) {
            this.radiusServers = radiusServers;
            return this;
        }

        /** The first member's ports (default: free ones). */
        public Builder basePort(int basePort) {
            this.basePort = basePort;
            return this;
        }

        /** The gateways' RADIUS ports, 0 for a free one (default: all free). */
        public Builder radiusPorts(int... radiusPorts) {
            this.radiusPorts = radiusPorts.clone();
            return this;
        }

        /** Snapshots this often; zero (the default) for none. */
        public Builder snapshotInterval(Duration snapshotInterval) {
            this.snapshotInterval = snapshotInterval;
            return this;
        }

        /** An exporter on every member, with each member's settings. */
        public Builder export(java.util.function.IntFunction<ExportConfig> export) {
            this.export = export;
            return this;
        }

        /**
         * Log purge settings from the first start: an archive recording keeps the segment length it was created with,
         * so changing {@code archive.segment.length} later does not affect the existing log.
         */
        public Builder purge(LogPurgeConfig purge) {
            this.purge = purge;
            return this;
        }

        /** State machine settings: tombstones, idle timeouts and capacities in seconds instead of hours. */
        public Builder settings(AccountingStateMachine.Settings settings) {
            this.settings = settings;
            return this;
        }

        /** The housekeeping timer ({@code service.sweep.interval}). */
        public Builder sweepInterval(Duration sweepInterval) {
            this.sweepInterval = sweepInterval;
            return this;
        }

        public LocalCluster start() {
            LocalCluster cluster = new LocalCluster(
                    baseDir, basePort < 0 ? freePortBase(members) : basePort, members, snapshotInterval);
            cluster.export = export;
            cluster.purge = purge;
            cluster.settings = settings;
            cluster.sweepInterval = sweepInterval;
            return launch(cluster, members, radiusServers, radiusPorts == null ? new int[radiusServers] : radiusPorts);
        }
    }

    private static LocalCluster launch(LocalCluster cluster, int members, int serverCount, int[] radiusPorts) {
        try {
            Reports.step("start " + members + " members and " + serverCount + " gateways", () -> {
                for (int i = 0; i < members; i++) {
                    cluster.startNode(i);
                }
                for (int g = 0; g < serverCount; g++) {
                    cluster.startServer(g + 1, radiusPorts[g]);
                }
            });
            return cluster;
        } catch (RuntimeException e) {
            cluster.close();
            throw e;
        }
    }

    public List<String> members() {
        List<String> members = new ArrayList<>();
        for (int i = 0; i < memberCount; i++) {
            members.add("localhost");
        }
        return members;
    }

    public int basePort() {
        return basePort;
    }

    public ClusterNodeConfig nodeConfig(int id) {
        return new ClusterNodeConfig(
                id,
                members(),
                basePort,
                new File(baseDir, "data/node-" + id),
                new File(baseDir, "aeron/node-" + id).getPath(),
                Profile.SMALL,
                Duration.ofMillis(1500),
                Duration.ofMillis(500),
                Duration.ofSeconds(10),
                snapshotInterval,
                2,
                0,
                256,
                settings,
                sweepInterval,
                export.apply(id),
                purge);
    }

    public void startNode(int id) {
        if (nodes[id] != null) {
            throw new IllegalStateException("node " + id + " already running");
        }
        Reports.step("start member " + id, () -> {
            nodes[id] = ClusterNode.launch(nodeConfig(id), null);
        });
    }

    /** Stops a member (graceful close; for kill -9 use the e2e tests). */
    public void stopNode(int id) {
        Reports.step("stop member " + id, () -> {
            CloseHelper.close(nodes[id]);
            nodes[id] = null;
        });
    }

    public ClusterNode node(int id) {
        return nodes[id];
    }

    public RadiusServer startServer(int serverId, int radiusPort) {
        return startServer(serverId, radiusPort, registry());
    }

    /** A gateway with its own NAS entries, e.g. {@link #registry(NasClient.Identity...)} for devices behind NAT. */
    public RadiusServer startServer(int serverId, int radiusPort, NasRegistry registry) {
        return startServer(serverId, radiusPort, registry, AuthConfig.DISABLED, dictionary -> null);
    }

    /** A gateway that also answers Access-Requests, with the handler made once the dictionary is loaded. */
    public RadiusServer startServer(
            int serverId,
            int radiusPort,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<io.radiusward.radius.dictionary.Dictionary, AccessHandler> handler) {
        return startServer(serverId, radiusPort, registry, auth, handler, RadsecConfig.DISABLED);
    }

    /** As above, also accepting RadSec connections (ADR 0034). */
    public RadiusServer startServer(
            int serverId,
            int radiusPort,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<io.radiusward.radius.dictionary.Dictionary, AccessHandler> handler,
            RadsecConfig radsec) {
        return startServer(serverId, radiusPort, registry, auth, handler, radsec, CoaConfig.DISABLED);
    }

    /** As above, also sending CoA and Disconnect-Requests (ADR 0036). */
    public RadiusServer startServer(
            int serverId,
            int radiusPort,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<io.radiusward.radius.dictionary.Dictionary, AccessHandler> handler,
            RadsecConfig radsec,
            CoaConfig coa) {
        return startServer(serverId, radiusPort, registry, auth, handler, radsec, coa, ProxyConfig.DISABLED);
    }

    /** As above, also proxying realms and relaying CoA from their home servers (ADR 0037, ADR 0043). */
    public RadiusServer startServer(
            int serverId,
            int radiusPort,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<io.radiusward.radius.dictionary.Dictionary, AccessHandler> handler,
            RadsecConfig radsec,
            CoaConfig coa,
            ProxyConfig proxy) {
        return startServer(serverId, radiusPort, registry, auth, handler, radsec, coa, proxy, "127.0.0.1");
    }

    /** As above, listening on {@code listenHost} ({@code 0.0.0.0} for peers in containers). */
    public RadiusServer startServer(
            int serverId,
            int radiusPort,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<io.radiusward.radius.dictionary.Dictionary, AccessHandler> handler,
            RadsecConfig radsec,
            CoaConfig coa,
            ProxyConfig proxy,
            String listenHost) {
        ServerConfig config = new ServerConfig(
                serverId,
                listenHost,
                radiusPort,
                1 << 20,
                members(),
                basePort,
                "localhost",
                Profile.SMALL,
                4096,
                Duration.ofSeconds(5),
                Duration.ofSeconds(1),
                Duration.ofSeconds(30),
                false,
                Profile.SMALL.idleStrategyName(),
                new File(baseDir, "aeron/gateway-" + serverId).getPath(),
                null,
                Duration.ZERO);
        RadiusServer radiusServer = Reports.step(
                "start gateway " + serverId,
                () -> RadiusServer.builder(config, registry)
                        .auth(auth)
                        .handlerFactory(handler)
                        .radsec(radsec)
                        .coa(coa)
                        .proxy(proxy)
                        .start());
        radiusServers.add(radiusServer);
        return radiusServer;
    }

    public static NasRegistry registry() {
        return registry(new NasClient.Identity[0]);
    }

    /** The local NAS entry (127.0.0.1); with {@code identity}, the devices behind it are told apart (ADR 0019). */
    public static NasRegistry registry(NasClient.Identity... identity) {
        return NasRegistry.of(List.of(NasClient.builder(NAS_NAME, NAS_ID)
                .network(0x7F000001, 32)
                .secret(SECRET.getBytes(StandardCharsets.US_ASCII))
                .messageAuthenticator(NasClient.MessageAuthenticatorPolicy.OPTIONAL)
                .identity(identity)
                .build()));
    }

    public RadiusServer radiusServer(int index) {
        return radiusServers.get(index);
    }

    public List<RadiusServer> radiusServers() {
        return radiusServers;
    }

    /** Waits for a leader among the running members and returns it. */
    public ClusterNode awaitLeader() {
        ClusterNode[] leader = new ClusterNode[1];
        await(Duration.ofSeconds(30), "leader elected", () -> {
            for (ClusterNode n : nodes) {
                if (n != null && "LEADER".equals(n.stats().role())) {
                    leader[0] = n;
                    return true;
                }
            }
            return false;
        });
        return leader[0];
    }

    /** Waits until every gateway is connected to the cluster. */
    public void awaitServersConnected() {
        Reports.step(
                "gateways connected",
                () -> await(
                        Duration.ofSeconds(30),
                        "gateways connected",
                        () -> radiusServers.stream().allMatch(g -> g.stats().connected())));
    }

    /** Waits until all running members applied the same log (same applied count and digest). */
    public void awaitConverged() {
        Reports.step("replicas converged", () -> awaitConvergedQuietly());
    }

    private void awaitConvergedQuietly() {
        await(Duration.ofSeconds(30), "replicas converged", () -> {
            Long digest = null;
            Long applied = null;
            for (ClusterNode n : nodes) {
                if (n == null) {
                    continue;
                }
                if (digest == null) {
                    digest = n.stats().digest();
                    applied = n.stats().applied();
                } else if (n.stats().digest() != digest || n.stats().applied() != applied) {
                    return false;
                }
            }
            return digest != null;
        });
    }

    public AdminClient admin() {
        return new AdminClient(members(), basePort);
    }

    /** {@link Await#until}. */
    public static void await(Duration timeout, String what, BooleanSupplier condition) {
        Await.until(timeout, what, condition);
    }

    /** {@link Ports#freePortBase}. */
    public static int freePortBase(int members) {
        return Ports.freePortBase(members);
    }

    /** {@link Ports#freePort}. */
    public static int freePort() {
        return Ports.freePort();
    }

    @Override
    public void close() {
        radiusServers.forEach(CloseHelper::quietClose);
        radiusServers.clear();
        for (int i = 0; i < nodes.length; i++) {
            CloseHelper.quietClose(nodes[i]);
            nodes[i] = null;
        }
    }
}
