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
    private final AccessHandler handler;
    private final AgentRunner[] runners;
    private RadsecAgent radsecAgent;
    private DynamicAuthorization dynamicAuthorization;
    private CoaService coaService;
    private CoaApi coaApi;
    private java.util.List<AccessWorker> workers = java.util.List.of();
    private Dictionary dictionary;
    private StoreSweep sweep;
    private CoaRelay coaRelay;
    private DynamicClients dynamicClients;

    private Gateway(
            GatewayConfig config,
            GatewayStats stats,
            MediaDriver driver,
            UdpAgent udpAgent,
            AuthAgent authAgent,
            AuthStats authStats,
            AccessHandler handler,
            AgentRunner... runners) {
        this.config = config;
        this.stats = stats;
        this.driver = driver;
        this.udpAgent = udpAgent;
        this.authAgent = authAgent;
        this.authStats = authStats;
        this.handler = handler;
        this.runners = runners;
    }

    public static Gateway launch(GatewayConfig config, NasRegistry registry) {
        return launchWith(config, registry, AuthConfig.DISABLED, dictionary -> null);
    }

    /**
     * A gateway that also answers Access-Requests when {@code auth} is enabled (Phase 5), deciding them with
     * {@code handler} on {@link AuthConfig#workers()} threads.
     */
    public static Gateway launch(GatewayConfig config, NasRegistry registry, AuthConfig auth, AccessHandler handler) {
        return launchWith(config, registry, auth, dictionary -> handler);
    }

    /**
     * As above, with the handler created from the gateway's dictionary (reply attributes are encoded with it); the
     * handler is closed with the gateway when it is {@link AutoCloseable}.
     */
    public static Gateway launchWith(
            GatewayConfig config,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<Dictionary, AccessHandler> handlerFactory) {
        return launchWith(config, registry, auth, handlerFactory, RadsecConfig.DISABLED);
    }

    /** As above, also listening for RadSec connections when {@code radsec} is enabled (ADR 0034). */
    public static Gateway launchWith(
            GatewayConfig config,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<Dictionary, AccessHandler> handlerFactory,
            RadsecConfig radsec) {
        return launchWith(config, registry, auth, handlerFactory, radsec, CoaConfig.DISABLED);
    }

    /** As above, also sending CoA and Disconnect-Requests when {@code coa} is enabled (ADR 0036). */
    public static Gateway launchWith(
            GatewayConfig config,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<Dictionary, AccessHandler> handlerFactory,
            RadsecConfig radsec,
            CoaConfig coa) {
        return launchWith(config, registry, auth, handlerFactory, radsec, coa, ProxyConfig.DISABLED);
    }

    /** As above, also proxying realms to home servers when {@code proxy} is enabled (ADR 0037). */
    public static Gateway launchWith(
            GatewayConfig config,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<Dictionary, AccessHandler> handlerFactory,
            RadsecConfig radsec,
            CoaConfig coa,
            ProxyConfig proxy) {
        if (proxy.enabled() && !auth.enabled()) {
            throw new IllegalArgumentException("proxy.enabled needs gateway.auth.enabled");
        }
        DictionaryLoader.Builder dictionaries = DictionaryLoader.builder().addBundledFreeRadius(ParseMode.LENIENT);
        if (config.dictionaryDir() != null) {
            dictionaries.addDirectory(config.dictionaryDir(), ParseMode.LENIENT);
        }
        Dictionary dictionary = dictionaries.load();
        dictionary.warnings().forEach(w -> LOG.warn("dictionary: {}", w));
        AccessHandler handler = auth.enabled() ? handlerFactory.apply(dictionary) : null;
        if (auth.enabled() && handler == null) {
            throw new IllegalArgumentException("authentication enabled without an access handler");
        }

        MediaDriver driver = MediaDriver.launchEmbedded(new MediaDriver.Context()
                .aeronDirectoryName(config.aeronDir())
                .threadingMode(ThreadingMode.SHARED)
                .publicationTermBufferLength(config.profile().termLength())
                .ipcTermBufferLength(config.profile().ipcTermLength())
                .dirDeleteOnStart(true)
                .dirDeleteOnShutdown(true));
        try {
            java.util.concurrent.atomic.AtomicReference<CoaService> coaHolder =
                    new java.util.concurrent.atomic.AtomicReference<>();
            GatewayStats stats = new GatewayStats();
            OneToOneRingBuffer toCluster = ring();
            OneToOneRingBuffer fromCluster = ring();
            java.util.Map<String, Integer> radsecIndex = new java.util.TreeMap<>();
            java.util.Map<String, Integer> dtlsIndex = new java.util.TreeMap<>();
            java.util.Map<String, Integer> tcpIndex = new java.util.TreeMap<>();
            RadsecLink link = radsec.enabled() ? radsecLink(registry, radsec, radsecIndex, dtlsIndex, tcpIndex) : null;
            UdpAgent udp = new UdpAgent(
                    config,
                    registry,
                    VendorFormats.from(dictionary),
                    toCluster,
                    fromCluster,
                    stats,
                    System::nanoTime,
                    link);
            AeronCluster.Context clusterContext = new AeronCluster.Context()
                    .aeronDirectoryName(driver.aeronDirectoryName())
                    .ingressChannel("aeron:udp?" + config.profile().termLengthParam())
                    .ingressEndpoints(ingressEndpoints(config))
                    .egressChannel("aeron:udp?endpoint=" + config.egressHost() + ":0")
                    .messageTimeoutNs(Duration.ofSeconds(5).toNanos())
                    .errorHandler(t -> LOG.warn("cluster client: {}", t.getMessage()));
            ClusterReservations reservations = auth.enabled()
                    ? new ClusterReservations(
                            auth.workers(), config.gatewayId(), auth.reservationTimeout(), auth.reservationTtl())
                    : null;
            ClusterClientAgent client =
                    new ClusterClientAgent(clusterContext, toCluster, fromCluster, stats, reservations);
            AuthStats authStats = new AuthStats();
            AuthAgent authAgent = null;
            java.util.List<AgentRunner> runnerList = new java.util.ArrayList<>();
            java.util.List<org.agrona.concurrent.Agent> socketAgents =
                    new java.util.ArrayList<>(java.util.List.of(udp));
            java.util.List<AccessWorker> workers = new java.util.ArrayList<>();
            if (auth.enabled()) {
                AccessSlots slots = new AccessSlots(auth.pending());
                authAgent = new AuthAgent(config, auth, registry, slots, authStats, System::nanoTime, link);
                if (proxy.enabled()) {
                    authAgent.proxy(proxy);
                    if (proxy.inner() && handler instanceof StoreAccessHandler stores) {
                        stores.proxyInner(new InnerProxy(proxy)); // ADR 0044
                    }
                }
                socketAgents.add(authAgent);
                for (int w = 0; w < auth.workers(); w++) {
                    // workers may wait on an identity store: a parking idle strategy, never a busy spin
                    AccessWorker worker = new AccessWorker(
                            w,
                            slots,
                            handler,
                            authStats,
                            coa.disconnectOldest()
                                    ? new DisconnectOldest(
                                            reservations.forWorker(w), coaHolder::get, coa.simultaneousUseWait())
                                    : reservations.forWorker(w));
                    workers.add(worker);
                    runnerList.add(new AgentRunner(
                            new org.agrona.concurrent.BackoffIdleStrategy(10, 20, 1_000, 1_000_000),
                            Gateway::error,
                            null,
                            worker));
                }
            }
            RadsecAgent radsecAgent = null;
            if (link != null) {
                radsecAgent = new RadsecAgent(
                        radsec, registry, link, radsecIndex, dtlsIndex, tcpIndex, auth.enabled(), System::nanoTime);
                socketAgents.add(radsecAgent);
            }
            ClusterQueries queries = null;
            DynamicAuthorization dynamic = null;
            if (coa.enabled()) {
                queries = new ClusterQueries();
                client.queries(queries);
                dynamic = new DynamicAuthorization(coa, config.listenHost(), link);
                socketAgents.add(dynamic);
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
            Gateway gateway = new Gateway(config, stats, driver, udp, authAgent, authStats, handler, runners);
            gateway.radsecAgent = radsecAgent;
            gateway.workers = java.util.List.copyOf(workers);
            gateway.dictionary = dictionary;
            gateway.dynamicClients = registry.dynamic();
            if (dynamic != null) {
                gateway.dynamicAuthorization = dynamic;
                gateway.coaService = new CoaService(
                        coa, registry, queries, dynamic, dictionary, link, radsecIndex, dtlsIndex, radsecAgent);
                coaHolder.set(gateway.coaService);
                if (coa.sweep().enabled() && handler instanceof StoreAccessHandler stores) {
                    gateway.sweep = new StoreSweep(coa.sweep(), gateway.coaService, stores);
                    gateway.sweep.start();
                }
                if (coa.token() != null) {
                    gateway.coaApi = new CoaApi(gateway.coaService, coa.token());
                }
                if (proxy.coaRelay()) {
                    gateway.coaRelay = new CoaRelay(proxy, gateway.coaService, config.listenHost());
                    try {
                        gateway.coaRelay.start();
                    } catch (java.io.IOException e) {
                        throw new IllegalStateException(
                                "cannot bind the CoA relay to " + config.listenHost() + ":" + proxy.coaPort(), e);
                    }
                }
            } else if (proxy.coaRelay()) {
                throw new IllegalArgumentException("home.<id>.coa needs coa.enabled: the relay finds sessions and"
                        + " sends to the NAS like the gateway's own CoA");
            }
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

    /**
     * The access handler of a gateway with identity stores ({@code auth.stores}, ADR 0021): what {@code gateway} runs
     * with {@code gateway.auth.enabled=true}.
     */
    public static java.util.function.Function<Dictionary, AccessHandler> storeHandler(
            io.radiusward.common.config.Config config, AuthConfig auth) {
        UsageCounters counters = UsageCounters.from(config);
        java.time.ZoneId zone = UsageCounters.zone(config);
        IpPools pools = IpPools.from(config);
        return dictionary -> {
            StoreAccessHandler handler = new StoreAccessHandler(
                    AuthStores.from(config, auth.workers(), dictionary), dictionary, System::currentTimeMillis);
            handler.limits(counters, zone); // ADR 0049
            handler.pools(pools); // ADR 0050
            handler.rules(RulesFile.from(config, name -> dictionary.find(name) != null)); // ADR 0051
            return handler;
        };
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

    /**
     * The NAS entries allowed over RadSec, then those allowed over DTLS, each with the secret of that transport; the
     * same ids as over UDP, so events dedup across all three.
     */
    private static RadsecLink radsecLink(
            NasRegistry registry,
            RadsecConfig radsec,
            java.util.Map<String, Integer> index,
            java.util.Map<String, Integer> dtlsIndex,
            java.util.Map<String, Integer> tcpIndex) {
        java.util.List<NasClient> clients = new java.util.ArrayList<>();
        addLinkClients(registry, radsec.clients(), "radsec", clients, index);
        addLinkClients(registry, radsec.dtls().clients(), "dtls", clients, dtlsIndex);
        java.util.Map<String, RadsecConfig.Client> plain = new java.util.TreeMap<>();
        for (String name : radsec.plain().clients()) {
            registry.clients().stream()
                    .filter(c -> c.name().equals(name))
                    .findFirst()
                    .ifPresent(n -> plain.put(name, new RadsecConfig.Client(n.secret(), null))); // the UDP secret
        }
        addLinkClients(registry, plain, "tcp", clients, tcpIndex);
        return new RadsecLink(clients.toArray(NasClient[]::new));
    }

    private static void addLinkClients(
            NasRegistry registry,
            java.util.Map<String, RadsecConfig.Client> allowed,
            String key,
            java.util.List<NasClient> clients,
            java.util.Map<String, Integer> index) {
        allowed.keySet().stream().sorted().forEach(name -> {
            NasClient n = registry.clients().stream()
                    .filter(c -> c.name().equals(name))
                    .findFirst()
                    .orElseThrow(() -> new io.radiusward.common.config.ConfigException(
                            "nas." + name + "." + key + ": no such NAS entry"));
            index.put(name, clients.size());
            clients.add(new NasClient(
                    n.name(),
                    n.id(),
                    n.network(),
                    n.prefixLength(),
                    allowed.get(name).secret(),
                    n.vendor(),
                    n.messageAuthenticator(),
                    n.identity(),
                    n.idleTimeoutMinutes(),
                    n.accessMessageAuthenticator()));
        });
    }

    /** RadSec port actually bound, -1 without RadSec; waits briefly for the bind. */
    public int radsecPort() {
        if (radsecAgent == null) {
            return -1;
        }
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!radsecAgent.bound() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        return radsecAgent.localPort();
    }

    /** A plain TCP port actually bound (authentication or accounting), -1 without it; waits briefly for the bind. */
    public int tcpPort(boolean authentication) {
        if (radsecAgent == null) {
            return -1;
        }
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!radsecAgent.bound() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        return radsecAgent.localTcpPort(authentication);
    }

    /** DTLS port actually bound, -1 without DTLS; waits briefly for the bind. */
    public int dtlsPort() {
        if (radsecAgent == null) {
            return -1;
        }
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!radsecAgent.bound() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        return radsecAgent.localDtlsPort();
    }

    /** The CoA relay's port, -1 without it (ADR 0043). */
    public int coaRelayPort() {
        return coaRelay == null ? -1 : coaRelay.port();
    }

    CoaRelay coaRelay() {
        return coaRelay;
    }

    RadsecAgent radsecAgent() {
        return radsecAgent;
    }

    /** CoA and Disconnect (ADR 0036), {@code null} unless {@code coa.enabled}. */
    public CoaService coa() {
        return coaService;
    }

    /** The CoA HTTP API for the management server ({@code /coa/}), {@code null} without {@code coa.api.token}. */
    /**
     * Per-request traces of Access-Requests ({@code trace.*}, ADR 0052) on every worker.
     *
     * @return the {@code /trace} API for the management server, {@code null} without {@code trace.api.token}
     */
    public com.sun.net.httpserver.HttpHandler trace(io.radiusward.common.config.Config raw) {
        if (dictionary == null) {
            return null;
        }
        Tracer tracer = Tracer.from(raw, dictionary);
        for (AccessWorker worker : workers) {
            worker.tracer(tracer);
        }
        String token = raw.string("trace.api.token", "").trim();
        return token.isEmpty() ? null : tracer.api(token);
    }

    public com.sun.net.httpserver.HttpHandler coaApi() {
        return coaApi;
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
        if (radsecAgent != null && !radsecAgent.bound()) {
            return Health.down("RadSec socket not bound");
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
            if (handler != null) {
                handler.writeMetrics(w, id);
            }
        }
        if (radsecAgent != null) {
            radsecAgent.writeMetrics(w, id);
        }
        if (dynamicAuthorization != null) {
            dynamicAuthorization.writeMetrics(w, id);
            coaService.writeMetrics(w, id);
        }
        if (sweep != null) {
            sweep.writeMetrics(w, id);
        }
        if (coaRelay != null) {
            coaRelay.writeMetrics(w, id);
        }
        if (dynamicClients != null) {
            dynamicClients.writeMetrics(w, id);
        }
        if (handler instanceof StoreAccessHandler stores && stores.innerProxy() != null) {
            stores.innerProxy().writeMetrics(w, id);
        }
        if (authAgent != null && authAgent.proxy() != null) {
            authAgent.proxy().writeMetrics(w, id);
        }
        w.counter("radiusward_log_messages_dropped_total", "Log messages dropped because the logging ring was full")
                .sample(NonBlockingQueueFullPolicy.dropped());
        JvmMetrics.write(w);
        return w.finish();
    }

    @Override
    public void close() {
        if (coaApi != null) {
            coaApi.close();
        }
        if (sweep != null) {
            sweep.stop();
        }
        if (coaRelay != null) {
            coaRelay.close();
        }
        if (dynamicClients != null) {
            dynamicClients.close();
        }
        CloseHelper.closeAll(runners);
        if (handler instanceof AutoCloseable closeable) {
            CloseHelper.quietClose(closeable); // identity stores: connections, files
        }
        CloseHelper.close(driver);
        LOG.info("gateway {} stopped", config.gatewayId());
    }
}
