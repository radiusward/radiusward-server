/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.aeron.cluster.client.AeronCluster;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.radiusward.common.Profile;
import io.radiusward.common.logging.NonBlockingQueueFullPolicy;
import io.radiusward.common.management.Health;
import io.radiusward.common.management.JsonWriter;
import io.radiusward.common.management.JvmMetrics;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import io.radiusward.radius.dictionary.ParseMode;
import java.time.Duration;
import org.agrona.BufferUtil;
import org.agrona.CloseHelper;
import org.agrona.concurrent.AgentRunner;
import org.agrona.concurrent.CompositeAgent;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.OneToOneRingBuffer;
import org.agrona.concurrent.ringbuffer.RingBufferDescriptor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A running gateway: embedded Aeron media driver, the UDP agent and the cluster client agent connected by two
 * ring buffers, on one thread ({@code shared}) or two ({@code dedicated}).
 */
public final class Gateway implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(Gateway.class);

    private static final int RING_CAPACITY = 1 << 22; // 4 MiB each way

    private final GatewayConfig config;
    private final GatewayStats stats;
    private final MediaDriver driver;
    private final UdpAgent udpAgent;
    private final AuthAgent authAgent;
    private final AuthStats authStats;
    private final AgentRunner[] runners;

    private Gateway(
            GatewayConfig config,
            GatewayStats stats,
            MediaDriver driver,
            UdpAgent udpAgent,
            AuthAgent authAgent,
            AuthStats authStats,
            AgentRunner... runners) {
        this.config = config;
        this.stats = stats;
        this.driver = driver;
        this.udpAgent = udpAgent;
        this.authAgent = authAgent;
        this.authStats = authStats;
        this.runners = runners;
    }

    public static Gateway launch(GatewayConfig config, NasRegistry registry) {
        return launch(config, registry, AuthConfig.DISABLED, null);
    }

    /**
     * A gateway that also answers Access-Requests when {@code auth} is enabled (Phase 5), deciding them with
     * {@code handler} on {@link AuthConfig#workers()} threads.
     */
    public static Gateway launch(GatewayConfig config, NasRegistry registry, AuthConfig auth, AccessHandler handler) {
        if (auth.enabled() && handler == null) {
            throw new IllegalArgumentException("authentication enabled without an access handler");
        }
        DictionaryLoader.Builder dictionaries = DictionaryLoader.builder().addBundledFreeRadius(ParseMode.LENIENT);
        if (config.dictionaryDir() != null) {
            dictionaries.addDirectory(config.dictionaryDir(), ParseMode.LENIENT);
        }
        Dictionary dictionary = dictionaries.load();
        dictionary.warnings().forEach(w -> LOG.warn("dictionary: {}", w));

        MediaDriver driver = MediaDriver.launchEmbedded(new MediaDriver.Context()
                .aeronDirectoryName(config.aeronDir())
                .threadingMode(ThreadingMode.SHARED)
                .publicationTermBufferLength(config.profile().termLength())
                .ipcTermBufferLength(config.profile().ipcTermLength())
                .dirDeleteOnStart(true)
                .dirDeleteOnShutdown(true));
        try {
            GatewayStats stats = new GatewayStats();
            OneToOneRingBuffer toCluster = ring();
            OneToOneRingBuffer fromCluster = ring();
            UdpAgent udp = new UdpAgent(
                    config, registry, VendorFormats.from(dictionary), toCluster, fromCluster, stats, System::nanoTime);
            AeronCluster.Context clusterContext = new AeronCluster.Context()
                    .aeronDirectoryName(driver.aeronDirectoryName())
                    .ingressChannel("aeron:udp?" + config.profile().termLengthParam())
                    .ingressEndpoints(ingressEndpoints(config))
                    .egressChannel("aeron:udp?endpoint=" + config.egressHost() + ":0")
                    .messageTimeoutNs(Duration.ofSeconds(5).toNanos())
                    .errorHandler(t -> LOG.warn("cluster client: {}", t.getMessage()));
            ClusterClientAgent client = new ClusterClientAgent(clusterContext, toCluster, fromCluster, stats);
            AuthStats authStats = new AuthStats();
            AuthAgent authAgent = null;
            java.util.List<AgentRunner> runnerList = new java.util.ArrayList<>();
            java.util.List<org.agrona.concurrent.Agent> socketAgents =
                    new java.util.ArrayList<>(java.util.List.of(udp));
            if (auth.enabled()) {
                AccessSlots slots = new AccessSlots(auth.pending());
                authAgent = new AuthAgent(config, auth, registry, slots, authStats, System::nanoTime);
                socketAgents.add(authAgent);
                for (int w = 0; w < auth.workers(); w++) {
                    // workers may wait on an identity store: a parking idle strategy, never a busy spin
                    runnerList.add(new AgentRunner(
                            new org.agrona.concurrent.BackoffIdleStrategy(10, 20, 1_000, 1_000_000),
                            Gateway::error,
                            null,
                            new AccessWorker(w, slots, handler, authStats)));
                }
            }
            if (config.dedicatedThreads()) {
                for (org.agrona.concurrent.Agent agent : socketAgents) {
                    runnerList.add(
                            new AgentRunner(Profile.idleStrategy(config.idleStrategy()), Gateway::error, null, agent));
                }
                runnerList.add(
                        new AgentRunner(Profile.idleStrategy(config.idleStrategy()), Gateway::error, null, client));
            } else {
                socketAgents.add(client);
                runnerList.add(new AgentRunner(
                        Profile.idleStrategy(config.idleStrategy()),
                        Gateway::error,
                        null,
                        new CompositeAgent(socketAgents)));
            }
            AgentRunner[] runners = runnerList.toArray(AgentRunner[]::new);
            for (AgentRunner runner : runners) {
                AgentRunner.startOnThread(runner);
            }
            Gateway gateway = new Gateway(config, stats, driver, udp, authAgent, authStats, runners);
            LOG.info(
                    "gateway {} started: {} NAS, cluster {}, {} threads",
                    config.gatewayId(),
                    registry.clients().size(),
                    ingressEndpoints(config),
                    config.dedicatedThreads() ? "dedicated" : "shared");
            return gateway;
        } catch (RuntimeException e) {
            CloseHelper.quietClose(driver);
            throw e;
        }
    }

    static String ingressEndpoints(GatewayConfig config) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < config.clusterMembers().size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(i)
                    .append('=')
                    .append(config.clusterMembers().get(i))
                    .append(':')
                    .append(config.clusterBasePort() + 100 * i);
        }
        return sb.toString();
    }

    private static OneToOneRingBuffer ring() {
        return new OneToOneRingBuffer(new UnsafeBuffer(
                BufferUtil.allocateDirectAligned(RING_CAPACITY + RingBufferDescriptor.TRAILER_LENGTH, 64)));
    }

    private static void error(Throwable t) {
        LOG.error("gateway agent error", t);
    }

    public GatewayStats stats() {
        return stats;
    }

    public GatewayConfig config() {
        return config;
    }

    /** UDP port actually bound; waits briefly for the agent thread to bind. */
    public int radiusPort() {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!stats.bound() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        return udpAgent.localPort();
    }

    public AuthStats authStats() {
        return authStats;
    }

    /** Access-Request port actually bound, -1 when authentication is off; waits briefly for the bind. */
    public int authPort() {
        if (authAgent == null) {
            return -1;
        }
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!authStats.bound() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        return authAgent.localPort();
    }

    public Health health() {
        for (AgentRunner runner : runners) {
            if (runner.isClosed()) {
                return Health.down("agent stopped");
            }
        }
        return Health.up("gateway " + config.gatewayId() + " running");
    }

    /** Ready when the UDP socket is bound and the cluster session is up. */
    public Health ready() {
        if (!stats.bound()) {
            return Health.down("RADIUS socket not bound");
        }
        if (authAgent != null && !authStats.bound()) {
            return Health.down("RADIUS authentication socket not bound");
        }
        if (!stats.connected()) {
            return Health.down("not connected to the cluster");
        }
        return Health.up("connected");
    }

    public String stateJson() {
        JsonWriter json = new JsonWriter()
                .field("component", "gateway")
                .field("gatewayId", config.gatewayId())
                .field("connected", stats.connected())
                .field("pending", stats.pending())
                .field("responseCache", stats.cacheSize())
                .object("packets");
        for (GatewayStats.Counter c : GatewayStats.counters()) {
            json.field(c.name().toLowerCase(java.util.Locale.ROOT), stats.get(c));
        }
        json.end();
        if (authAgent != null) {
            json.object("access").field("inFlight", authStats.inFlight()).field("replyCache", authStats.cached());
            for (AuthStats.Counter c : AuthStats.counters()) {
                json.field(c.name().toLowerCase(java.util.Locale.ROOT), authStats.get(c));
            }
            json.end();
        }
        return json.object("log")
                .field("dropped", NonBlockingQueueFullPolicy.dropped())
                .end()
                .finish();
    }

    /** {@code /metrics}: every packet counter by result, pending requests, cache size, connection, JVM. */
    public String metrics() {
        String id = Integer.toString(config.gatewayId());
        PrometheusWriter w = new PrometheusWriter();
        w.counter("radiusward_gateway_packets_total", "RADIUS packets and requests by what happened to them");
        for (GatewayStats.Counter c : GatewayStats.counters()) {
            w.sample(stats.get(c), "gateway", id, "result", c.name().toLowerCase(java.util.Locale.ROOT));
        }
        w.gauge("radiusward_gateway_pending_requests", "Requests waiting for a commit")
                .sample(stats.pending(), "gateway", id);
        w.gauge("radiusward_gateway_response_cache_entries", "Entries in the RFC 5080 response cache")
                .sample(stats.cacheSize(), "gateway", id);
        w.gauge("radiusward_gateway_cluster_connected", "1 when connected to the cluster")
                .sample(stats.connected() ? 1 : 0, "gateway", id);
        if (authAgent != null) {
            w.counter("radiusward_gateway_access_requests_total", "Access-Requests by what happened to them");
            for (AuthStats.Counter c : AuthStats.counters()) {
                w.sample(authStats.get(c), "gateway", id, "result", c.name().toLowerCase(java.util.Locale.ROOT));
            }
            w.gauge("radiusward_gateway_access_in_flight", "Access-Requests handed to the workers, not answered yet")
                    .sample(authStats.inFlight(), "gateway", id);
            w.gauge("radiusward_gateway_access_reply_cache_entries", "Replies kept for retransmissions")
                    .sample(authStats.cached(), "gateway", id);
        }
        w.counter("radiusward_log_messages_dropped_total", "Log messages dropped because the logging ring was full")
                .sample(NonBlockingQueueFullPolicy.dropped());
        JvmMetrics.write(w);
        return w.finish();
    }

    @Override
    public void close() {
        CloseHelper.closeAll(runners);
        CloseHelper.close(driver);
        LOG.info("gateway {} stopped", config.gatewayId());
    }
}
