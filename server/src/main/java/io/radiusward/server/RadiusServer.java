/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.aeron.driver.MediaDriver;
import io.radiusward.common.logging.NonBlockingQueueFullPolicy;
import io.radiusward.common.management.Health;
import io.radiusward.common.management.JsonWriter;
import io.radiusward.common.management.JvmMetrics;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.dictionary.Dictionary;
import org.agrona.CloseHelper;
import org.agrona.concurrent.AgentRunner;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A running gateway: embedded Aeron media driver, the UDP agent and the cluster client agent connected by two
 * ring buffers, on one thread ({@code shared}) or two ({@code dedicated}).
 */
public final class RadiusServer implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(RadiusServer.class);

    private final ServerConfig config;
    private final ServerStats stats;
    private final MediaDriver driver;
    private final UdpAgent udpAgent;
    private final AuthAgent authAgent;
    private final AuthStats authStats;
    private final AccessHandler handler;
    private final AgentRunner[] runners;
    private final ClusterReservations reservations; // null without authentication
    private volatile boolean draining;

    /**
     * Reports not ready from now on while still answering, so a load balancer stops sending new requests before the
     * gateway closes (ADR 0062); requests in flight finish instead of costing the NAS a retransmission.
     */
    public void drain() {
        draining = true;
    }

    private final RadsecAgent radsecAgent;
    private final DynamicAuthorization dynamicAuthorization;
    private final CoaService coaService;
    private final CoaApi coaApi;
    private final java.util.List<AccessWorker> workers;
    private final Dictionary dictionary;
    private final NasRegistry registry;
    private Tracer tracer;
    private final StoreSweep sweep;
    private final CoaRelay coaRelay;
    private final DynamicClients dynamicClients;

    /** What {@link ServerAssembly} built and started; {@code null} for what is not configured. */
    record Parts(
            ServerConfig config,
            ServerStats stats,
            MediaDriver driver,
            UdpAgent udpAgent,
            AuthAgent authAgent,
            AuthStats authStats,
            AccessHandler handler,
            java.util.List<AgentRunner> runners,
            ClusterReservations reservations,
            RadsecAgent radsecAgent,
            java.util.List<AccessWorker> workers,
            NasRegistry registry,
            Dictionary dictionary,
            DynamicClients dynamicClients,
            DynamicAuthorization dynamicAuthorization,
            CoaService coaService,
            StoreSweep sweep,
            CoaApi coaApi,
            CoaRelay coaRelay) {}

    RadiusServer(Parts p) {
        this.config = p.config();
        this.stats = p.stats();
        this.driver = p.driver();
        this.udpAgent = p.udpAgent();
        this.authAgent = p.authAgent();
        this.authStats = p.authStats();
        this.handler = p.handler();
        this.runners = p.runners().toArray(AgentRunner[]::new);
        this.reservations = p.reservations();
        this.radsecAgent = p.radsecAgent();
        this.workers = java.util.List.copyOf(p.workers());
        this.registry = p.registry();
        this.dictionary = p.dictionary();
        this.dynamicClients = p.dynamicClients();
        this.dynamicAuthorization = p.dynamicAuthorization();
        this.coaService = p.coaService();
        this.sweep = p.sweep();
        this.coaApi = p.coaApi();
        this.coaRelay = p.coaRelay();
    }

    /** An accounting-only gateway. */
    public static RadiusServer launch(ServerConfig config, NasRegistry registry) {
        return builder(config, registry).start();
    }

    /**
     * A gateway with more than accounting: {@code RadiusServer.builder(config, registry).auth(auth).handler(handler)
     * .radsec(..).coa(..).proxy(..).start()}; every part is off unless given.
     */
    public static Builder builder(ServerConfig config, NasRegistry registry) {
        return new Builder(config, registry);
    }

    public static final class Builder {
        private final ServerConfig config;
        private final NasRegistry registry;
        private AuthConfig auth = AuthConfig.DISABLED;
        private java.util.function.Function<Dictionary, AccessHandler> handlerFactory = dictionary -> null;
        private RadsecConfig radsec = RadsecConfig.DISABLED;
        private CoaConfig coa = CoaConfig.DISABLED;
        private ProxyConfig proxy = ProxyConfig.DISABLED;

        private Builder(ServerConfig config, NasRegistry registry) {
            this.config = config;
            this.registry = registry;
        }

        /** Answers Access-Requests when {@code auth} is enabled (Phase 5), on {@link AuthConfig#workers()} threads. */
        public Builder auth(AuthConfig auth) {
            this.auth = auth;
            return this;
        }

        /** Decides Access-Requests. */
        public Builder handler(AccessHandler handler) {
            this.handlerFactory = dictionary -> handler;
            return this;
        }

        /**
         * Decides Access-Requests with a handler made from the gateway's dictionary (reply attributes are encoded with
         * it); closed with the gateway when it is {@link AutoCloseable}.
         */
        public Builder handlerFactory(java.util.function.Function<Dictionary, AccessHandler> handlerFactory) {
            this.handlerFactory = handlerFactory;
            return this;
        }

        /** Listens for RadSec connections and DTLS when enabled (ADR 0034, ADR 0038). */
        public Builder radsec(RadsecConfig radsec) {
            this.radsec = radsec;
            return this;
        }

        /** Sends CoA and Disconnect-Requests when enabled (ADR 0036). */
        public Builder coa(CoaConfig coa) {
            this.coa = coa;
            return this;
        }

        /** Proxies realms to home servers when enabled (ADR 0037). */
        public Builder proxy(ProxyConfig proxy) {
            this.proxy = proxy;
            return this;
        }

        public RadiusServer start() {
            return ServerAssembly.start(config, registry, auth, handlerFactory, radsec, coa, proxy);
        }
    }

    /**
     * The access handler of a gateway with identity stores ({@code auth.stores}, ADR 0021): what {@code gateway} runs
     * with {@code gateway.auth.enabled=true}.
     */
    public static java.util.function.Function<Dictionary, AccessHandler> storeHandler(
            io.radiusward.common.config.Config config, AuthConfig auth) {
        return dictionary -> {
            AccessPolicies policies = AccessPolicies.from(config, dictionary);
            StoreAccessHandler handler = new StoreAccessHandler(
                    AuthStores.from(config, auth.workers(), dictionary), dictionary, System::currentTimeMillis);
            handler.policies(policies);
            return handler;
        };
    }

    public ServerStats stats() {
        return stats;
    }

    public ServerConfig config() {
        return config;
    }

    /** UDP port actually bound; waits briefly for the agent thread to bind. */
    public int radiusPort() {
        awaitBound(() -> stats.bound());
        return udpAgent.localPort();
    }

    /** Waits up to 5 s for an agent to bind its socket (agents start on their own threads). */
    private static void awaitBound(java.util.function.BooleanSupplier bound) {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!bound.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
    }

    public AuthStats authStats() {
        return authStats;
    }

    /** Access-Request port actually bound, -1 when authentication is off; waits briefly for the bind. */
    public int authPort() {
        if (authAgent == null) {
            return -1;
        }
        awaitBound(() -> authStats.bound());
        return authAgent.localPort();
    }

    /** RadSec port actually bound, -1 without RadSec; waits briefly for the bind. */
    public int radsecPort() {
        if (radsecAgent == null) {
            return -1;
        }
        awaitBound(() -> radsecAgent.bound());
        return radsecAgent.localPort();
    }

    /** A plain TCP port actually bound (authentication or accounting), -1 without it; waits briefly for the bind. */
    public int tcpPort(boolean authentication) {
        if (radsecAgent == null) {
            return -1;
        }
        awaitBound(() -> radsecAgent.bound());
        return radsecAgent.localTcpPort(authentication);
    }

    /** DTLS port actually bound, -1 without DTLS; waits briefly for the bind. */
    public int dtlsPort() {
        if (radsecAgent == null) {
            return -1;
        }
        awaitBound(() -> radsecAgent.bound());
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

    /** {@code auth.reject.delay} (ADR 0057): 1 s by default, at most 5 s. */
    static java.time.Duration rejectDelay(io.radiusward.common.config.Config raw) {
        java.time.Duration d = raw.duration("auth.reject.delay", java.time.Duration.ofSeconds(1));
        if (d.isNegative() || d.compareTo(java.time.Duration.ofSeconds(5)) > 0) {
            throw new io.radiusward.common.config.ConfigException("auth.reject.delay: 0s to 5s");
        }
        return d;
    }

    private AuthLog authLog;

    /** The authentication log ({@code auth.log.*}, ADR 0058) for every worker; not changed by a reload. */
    public void authLog(io.radiusward.common.config.Config raw) {
        AuthLog log = AuthLog.from(raw);
        if (log == null) {
            return;
        }
        this.authLog = log;
        for (AccessWorker worker : workers) {
            worker.authLog(log);
        }
    }

    /** Holds Access-Rejects decided here back for {@code delay} before they are sent (ADR 0057). */
    public void rejectDelay(java.time.Duration delay) {
        if (authAgent != null) {
            authAgent.rejectDelay(delay);
        }
    }

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
        this.tracer = tracer;
        for (AccessWorker worker : workers) {
            worker.tracer(tracer);
        }
        String token = raw.string("trace.api.token", "").trim();
        return token.isEmpty() ? null : tracer.api(token);
    }

    /**
     * Applies a reloaded configuration (ADR 0054): NAS entries, identity stores and their per-NAS settings, usage
     * counters, IP pools, TOTP, rules and trace conditions. Everything is built first; a configuration that does not
     * load changes nothing. Listeners, RadSec/DTLS/TCP clients, the cluster, proxying and CoA keep their settings
     * until a restart.
     *
     * @return what was applied
     * @throws io.radiusward.common.config.ConfigException if the configuration does not load
     */
    public synchronized String reload(io.radiusward.common.config.Config raw) {
        NasRegistry fresh = NasRegistry.configured(raw);
        java.time.Duration delay = rejectDelay(raw);
        if (fresh.clients().isEmpty() && registry.dynamic() == null) {
            throw new io.radiusward.common.config.ConfigException(
                    "no NAS configured: add nas.<name>.address and nas.<name>.secret");
        }
        StoreAccessHandler stores = handler instanceof StoreAccessHandler h ? h : null;
        AuthStores nextStores = null;
        AccessPolicies policies = null;
        if (stores != null) {
            nextStores = AuthStores.from(raw, workers.size(), dictionary);
            try {
                policies = AccessPolicies.from(raw, dictionary);
            } catch (RuntimeException e) {
                nextStores.close();
                throw e;
            }
        }
        int before = registry.clients().size();
        registry.replace(fresh);
        rejectDelay(delay);
        if (stores != null) {
            stores.reload(nextStores, java.time.Duration.ofSeconds(30));
            stores.policies(policies);
        }
        if (tracer != null) {
            tracer.reconfigure(raw);
        }
        String summary = "NAS entries: " + fresh.clients().size() + " (were " + before + ")"
                + (stores != null ? ", stores: " + String.join(", ", nextStores.order()) : "");
        LOG.info("configuration reloaded: {}", summary);
        return summary;
    }

    /** The CoA HTTP API for the management server ({@code /coa/}), {@code null} without {@code coa.api.token}. */
    public com.sun.net.httpserver.HttpHandler coaApi() {
        return coaApi;
    }

    public Health health() {
        for (AgentRunner runner : runners) {
            if (runner.isClosed()) {
                return Health.down("agent stopped");
            }
        }
        return Health.up("gateway " + config.serverId() + " running");
    }

    /** Ready when the UDP socket is bound and the cluster session is up. */
    public Health ready() {
        if (draining) {
            return Health.down("draining before shutdown");
        }
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
                .field("serverId", config.serverId())
                .field("connected", stats.connected())
                .field("pending", stats.pending())
                .field("responseCache", stats.cacheSize())
                .object("packets");
        for (ServerStats.Counter c : ServerStats.counters()) {
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
        String id = Integer.toString(config.serverId());
        PrometheusWriter w = new PrometheusWriter();
        w.counter("radiusward_gateway_packets_total", "RADIUS packets and requests by what happened to them");
        for (ServerStats.Counter c : ServerStats.counters()) {
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
            w.counter("radiusward_gateway_access_rejects_total", "Access-Rejects by the cause the handler recorded");
            authStats.rejectsByCause().forEach((cause, n) -> w.sample(n, "gateway", id, "cause", cause));
            w.gauge("radiusward_gateway_access_in_flight", "Access-Requests handed to the workers, not answered yet")
                    .sample(authStats.inFlight(), "gateway", id);
            w.gauge("radiusward_gateway_access_reply_cache_entries", "Replies kept for retransmissions")
                    .sample(authStats.cached(), "gateway", id);
            if (handler != null) {
                handler.writeMetrics(w, id);
            }
            if (reservations != null) {
                reservations.writeMetrics(w, id);
            }
        }
        writeCertificateExpiry(w, id);
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
        if (authLog != null) {
            authLog.writeMetrics(w, id);
        }
        w.counter("radiusward_log_messages_dropped_total", "Log messages dropped because the logging ring was full")
                .sample(NonBlockingQueueFullPolicy.dropped());
        JvmMetrics.write(w);
        return w.finish();
    }

    /** When the server certificates of EAP and RadSec/DTLS expire, so an alert fires before they do. */
    private void writeCertificateExpiry(PrometheusWriter w, String id) {
        java.util.TreeMap<String, TlsCredentials> credentials = new java.util.TreeMap<>();
        if (handler instanceof StoreAccessHandler stores && stores.eapTls() != null) {
            credentials.put("eap", stores.eapTls());
        }
        if (radsecAgent != null && radsecAgent.credentials() != null) {
            credentials.put("radsec", radsecAgent.credentials());
        }
        if (credentials.isEmpty()) {
            return;
        }
        w.gauge(
                "radiusward_tls_certificate_expiry_timestamp_seconds",
                "When the server certificate in use expires (Unix time), by what it serves");
        credentials.forEach((use, c) -> w.sample(c.notAfterMillis() / 1000.0, "gateway", id, "use", use));
    }

    @Override
    public void close() {
        if (authLog != null) {
            authLog.close();
        }
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
        LOG.info("gateway {} stopped", config.serverId());
    }
}
