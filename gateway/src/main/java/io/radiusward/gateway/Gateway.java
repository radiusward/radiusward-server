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
    private final AgentRunner[] runners;

    private Gateway(
            GatewayConfig config, GatewayStats stats, MediaDriver driver, UdpAgent udpAgent, AgentRunner... runners) {
        this.config = config;
        this.stats = stats;
        this.driver = driver;
        this.udpAgent = udpAgent;
        this.runners = runners;
    }

    public static Gateway launch(GatewayConfig config, NasRegistry registry) {
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

            AgentRunner[] runners;
            if (config.dedicatedThreads()) {
                runners = new AgentRunner[] {
                    new AgentRunner(Profile.idleStrategy(config.idleStrategy()), Gateway::error, null, udp),
                    new AgentRunner(Profile.idleStrategy(config.idleStrategy()), Gateway::error, null, client)
                };
            } else {
                runners = new AgentRunner[] {
                    new AgentRunner(
                            Profile.idleStrategy(config.idleStrategy()),
                            Gateway::error,
                            null,
                            new CompositeAgent(udp, client))
                };
            }
            for (AgentRunner runner : runners) {
                AgentRunner.startOnThread(runner);
            }
            Gateway gateway = new Gateway(config, stats, driver, udp, runners);
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
        return json.end()
                .object("log")
                .field("dropped", NonBlockingQueueFullPolicy.dropped())
                .end()
                .finish();
    }

    @Override
    public void close() {
        CloseHelper.closeAll(runners);
        CloseHelper.close(driver);
        LOG.info("gateway {} stopped", config.gatewayId());
    }
}
