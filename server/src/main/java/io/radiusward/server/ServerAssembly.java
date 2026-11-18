/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.aeron.cluster.client.AeronCluster;
import io.aeron.driver.MediaDriver;
import io.aeron.driver.ThreadingMode;
import io.radiusward.common.Profile;
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
 * How a RADIUS server is put together and started: the dictionary, the embedded media driver, the rings to the cluster
 * client, the UDP, authentication, RadSec/DTLS and CoA agents with their threads (one each, or one composite), the
 * access workers, and the CoA service, sweep, API and relay. A failure on the way closes the media driver.
 */
final class ServerAssembly {

    private static final Logger LOG = LogManager.getLogger(RadiusServer.class);
    private static final int RING_CAPACITY = 1 << 22; // 4 MiB each way

    private ServerAssembly() {}

    /** Loads the dictionary, starts the media driver, builds the agents and workers, starts them, and the CoA parts. */
    static RadiusServer start(
            ServerConfig config,
            NasRegistry registry,
            AuthConfig auth,
            java.util.function.Function<Dictionary, AccessHandler> handlerFactory,
            RadsecConfig radsec,
            CoaConfig coa,
            ProxyConfig proxy) {
        if (proxy.enabled() && !auth.enabled()) {
            throw new IllegalArgumentException("proxy.enabled needs server.auth.enabled");
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
            ServerStats stats = new ServerStats();
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
                            auth.workers(), config.serverId(), auth.reservationTimeout(), auth.reservationTtl())
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
                    authAgent.proxy(proxy, dictionary); // the dictionary resolves rewrites (ADR 0055)
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
                            ServerAssembly::error,
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
                    runnerList.add(new AgentRunner(
                            Profile.idleStrategy(config.idleStrategy()), ServerAssembly::error, null, agent));
                }
                runnerList.add(new AgentRunner(
                        Profile.idleStrategy(config.idleStrategy()), ServerAssembly::error, null, client));
            } else {
                socketAgents.add(client);
                runnerList.add(new AgentRunner(
                        Profile.idleStrategy(config.idleStrategy()),
                        ServerAssembly::error,
                        null,
                        new CompositeAgent(socketAgents)));
            }
            for (AgentRunner runner : runnerList) {
                AgentRunner.startOnThread(runner);
            }
            CoaService coaService = null;
            StoreSweep sweep = null;
            CoaApi coaApi = null;
            CoaRelay coaRelay = null;
            if (dynamic != null) {
                coaService = new CoaService(
                        coa, registry, queries, dynamic, dictionary, link, radsecIndex, dtlsIndex, radsecAgent);
                coaHolder.set(coaService);
                if (coa.sweep().enabled() && handler instanceof StoreAccessHandler stores) {
                    sweep = new StoreSweep(coa.sweep(), coaService, stores);
                    sweep.start();
                }
                if (coa.token() != null) {
                    coaApi = new CoaApi(coaService, coa.token());
                }
                if (proxy.coaRelay()) {
                    coaRelay = new CoaRelay(proxy, coaService, config.listenHost());
                    try {
                        coaRelay.start();
                    } catch (java.io.IOException e) {
                        throw new IllegalStateException(
                                "cannot bind the CoA relay to " + config.listenHost() + ":" + proxy.coaPort(), e);
                    }
                }
            } else if (proxy.coaRelay()) {
                throw new IllegalArgumentException("home.<id>.coa needs coa.enabled: the relay finds sessions and"
                        + " sends to the NAS like the RADIUS server's own CoA");
            }
            RadiusServer radiusServer = new RadiusServer(new RadiusServer.Parts(
                    config,
                    stats,
                    driver,
                    udp,
                    authAgent,
                    authStats,
                    handler,
                    runnerList,
                    reservations,
                    radsecAgent,
                    workers,
                    registry,
                    dictionary,
                    registry.dynamic(),
                    dynamic,
                    coaService,
                    sweep,
                    coaApi,
                    coaRelay));
            LOG.info(
                    "RADIUS server {} started: {} NAS, cluster {}, {} threads",
                    config.serverId(),
                    registry.clients().size(),
                    ingressEndpoints(config),
                    config.dedicatedThreads() ? "dedicated" : "shared");
            return radiusServer;
        } catch (RuntimeException e) {
            CloseHelper.quietClose(driver);
            throw e;
        }
    }

    /** The cluster members' ingress endpoints: {@code <id>=<host>:<base port + 100 * id>}. */
    static String ingressEndpoints(ServerConfig config) {
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
        LOG.error("RADIUS server agent error", t);
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
            clients.add(n.withSecret(allowed.get(name).secret())); // an IPv6 entry keeps its network
        });
    }
}
