/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.ItemParser;
import io.radiusward.auth.UserRecord;
import io.radiusward.client.RadiusClient;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.node.ClusterNodeConfig;
import io.radiusward.common.config.Config;
import io.radiusward.export.AccountingSink;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SinkProvider;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.server.AuthConfig;
import io.radiusward.server.AuthPlugins;
import io.radiusward.server.CoaConfig;
import io.radiusward.server.CoaService;
import io.radiusward.server.EventKeys;
import io.radiusward.server.NasClient;
import io.radiusward.server.NasRegistry;
import io.radiusward.server.ProxyConfig;
import io.radiusward.server.RadiusServer;
import io.radiusward.server.RadsecConfig;
import io.radiusward.server.ServerConfig;
import io.radiusward.server.UserKeys;
import io.radiusward.tools.admin.AdminClient;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import org.agrona.CloseHelper;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * radiusward inside this JVM, for development and tests: one cluster member and one RADIUS server by default (or a
 * whole cluster: {@link Builder#members}, {@link Builder#radiusServers}), started with the same code and the same
 * settings as in production, with the developer's own identity stores, credential verifiers and sinks; ports chosen at
 * start; everything gone on {@link #close()}. <b>Not for production</b>: all members share one machine and nothing is
 * synced to disk.
 *
 * <pre>{@code
 * try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
 *         .user("alice", "secret", "Class := gold")
 *         .start();
 *         RadiusClient nas = radius.client()) {
 *     nas.pap("alice", "secret");                     // Access-Accept with Class
 * }
 * }</pre>
 *
 * The JVM needs {@code --add-exports java.base/jdk.internal.misc=ALL-UNNAMED} (Agrona and Aeron); {@link
 * Builder#start()} says so if it is missing.
 */
public final class EmbeddedRadiusward implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(EmbeddedRadiusward.class);

    /** The NAS entry when the builder names none: {@value}, from 127.0.0.1 with {@link #DEFAULT_SECRET}. */
    public static final String DEFAULT_NAS = "local";

    public static final String DEFAULT_SECRET = "testing123";

    static final String JVM_OPTION = "--add-exports java.base/jdk.internal.misc=ALL-UNNAMED";
    private static final Duration START_TIMEOUT = Duration.ofSeconds(30);
    private static final Set<String> TLS_METHODS = Set.of("tls", "peap", "ttls", "teap");

    private final Config config;
    private final Path directory;
    private final boolean deleteDirectory;
    private final ClusterNodeConfig[] memberConfigs;
    private final ClusterNode[] members;
    private final Config[] serverConfigs;
    private final RadiusServer[] servers;
    private final AuthPlugins plugins;
    private final NasRegistry registry;
    private final RecordingSink recorder;
    private final List<AutoCloseable> owned;
    private final ThrowawayPki pki;
    private final String host;
    private final String defaultSecret;
    private final String defaultNas;
    private AdminClient admin;

    private EmbeddedRadiusward(Builder b, Config config, Path directory, boolean deleteDirectory, ThrowawayPki pki) {
        this.config = config;
        this.directory = directory;
        this.deleteDirectory = deleteDirectory;
        this.pki = pki;
        this.recorder = b.recorder;
        this.owned = EmbeddedSettings.owned(b);
        this.plugins = EmbeddedSettings.plugins(b);
        this.host = config.string("server.listen.host");
        this.defaultSecret =
                b.nas.isEmpty() ? DEFAULT_SECRET : b.nas.values().iterator().next()[1];
        this.defaultNas =
                b.nas.isEmpty() ? DEFAULT_NAS : b.nas.keySet().iterator().next();
        SinkProvider[] sinkProviders = EmbeddedSettings.sinkProviders(b);
        memberConfigs = new ClusterNodeConfig[b.members];
        for (int i = 0; i < b.members; i++) {
            ClusterNodeConfig c = ClusterNodeConfig.from(config.with(Map.of(
                    "cluster.node.id", Integer.toString(i),
                    "cluster.aeron.dir", directory.resolve("aeron/member-" + i).toString())));
            memberConfigs[i] = withExport(c, c.export().withProviders(sinkProviders));
        }
        members = new ClusterNode[b.members];
        serverConfigs = new Config[b.radiusServers];
        for (int i = 0; i < b.radiusServers; i++) {
            Map<String, String> own = new LinkedHashMap<>();
            own.put("server.id", Integer.toString(i + 1));
            own.put(
                    "server.aeron.dir",
                    directory.resolve("aeron/server-" + (i + 1)).toString());
            if (i > 0) { // fixed ports are the first server's; the others take free ones
                own.put("server.listen.port", "0");
                own.put("server.auth.port", "0");
            }
            serverConfigs[i] = config.with(own);
        }
        servers = new RadiusServer[b.radiusServers];
        this.registry = NasRegistry.from(config);
    }

    public static Builder builder() {
        return new Builder();
    }

    // ---- where to send requests -------------------------------------------------------------------------------

    /** The port of the first RADIUS server that answers Access-Requests. */
    public int authPort() {
        return authPort(0);
    }

    /** The Access-Request port of RADIUS server {@code i} (0 is the first). */
    public int authPort(int i) {
        return running(i).authPort();
    }

    /** The port of the first RADIUS server that answers Accounting-Requests. */
    public int accountingPort() {
        return accountingPort(0);
    }

    public int accountingPort(int i) {
        return running(i).radiusPort();
    }

    /** The address the ports listen on ({@code 127.0.0.1} unless {@code server.listen.host} says otherwise). */
    public String host() {
        return host;
    }

    /** A client of {@link #authPort()} with the first NAS entry's secret; close it after use. */
    public RadiusClient client() {
        return client(0);
    }

    /** A client of RADIUS server {@code i}'s Access-Request port. */
    public RadiusClient client(int i) {
        return RadiusClient.udp(host, authPort(i), defaultSecret);
    }

    /** A client of {@link #accountingPort()} with the first NAS entry's secret; close it after use. */
    public RadiusClient accountingClient() {
        return accountingClient(0);
    }

    public RadiusClient accountingClient(int i) {
        return RadiusClient.udp(host, accountingPort(i), defaultSecret);
    }

    /** Where the members and the RADIUS servers keep their files. */
    public Path directory() {
        return directory;
    }

    /** The settings it runs with: its defaults, then the builder's. */
    public Config config() {
        return config;
    }

    /** The first RADIUS server, for what this class does not offer (statistics, reload). */
    public RadiusServer server() {
        return server(0);
    }

    /** RADIUS server {@code i}, {@code null} while stopped. */
    public synchronized RadiusServer server(int i) {
        return servers[i];
    }

    /** The first cluster member, {@code null} while stopped. */
    public ClusterNode member() {
        return member(0);
    }

    public synchronized ClusterNode member(int i) {
        return members[i];
    }

    private synchronized RadiusServer running(int i) {
        RadiusServer s = servers[i];
        if (s == null) {
            throw new IllegalStateException("RADIUS server " + i + " is stopped");
        }
        return s;
    }

    // ---- EAP --------------------------------------------------------------------------------------------------

    /**
     * The throwaway CA that signed the server's certificate (for {@code EapLogin.trust(...)}) and every {@link
     * #clientCertificate}; only when a TLS-based EAP method is on and no certificate is configured.
     */
    public X509Certificate ca() {
        return pki().ca();
    }

    /** A client certificate for EAP-TLS with {@code name} as its common name, signed by {@link #ca()}. */
    public ClientCertificate clientCertificate(String name) {
        return pki().client(name);
    }

    private ThrowawayPki pki() {
        if (pki == null) {
            throw new IllegalStateException("no throwaway CA: turn on tls, peap, ttls or teap with eap(...), without a"
                    + " certificate of your own (auth.eap.tls.certificate)");
        }
        return pki;
    }

    // ---- accounting --------------------------------------------------------------------------------------------

    /** The accounting events the cluster committed so far, in commit order (exported as to any sink). */
    public List<ExportEvent> accounting() {
        return recorder.events();
    }

    /** Waits until at least {@code count} accounting events are committed and exported; up to 10 s. */
    public List<ExportEvent> awaitAccounting(int count) {
        return awaitAccounting(count, Duration.ofSeconds(10));
    }

    public List<ExportEvent> awaitAccounting(int count, Duration timeout) {
        await(timeout, count + " accounting events", () -> recorder.size() >= count);
        return accounting();
    }

    /** The session of {@code acctSessionId} from the first NAS entry the builder named, as the cluster holds it. */
    public Optional<Session> session(String acctSessionId) {
        return session(defaultNas, acctSessionId);
    }

    /** The session of {@code acctSessionId} from NAS entry {@code nas}, as the cluster holds it. */
    public Optional<Session> session(String nas, String acctSessionId) {
        NasClient client = registry.clients().stream()
                .filter(c -> c.name().equals(nas))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("no NAS entry " + nas));
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(acctSessionId.getBytes(StandardCharsets.UTF_8));
        keys.compute(client.id(), 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        AdminClient.Session s = admin().session(keys.sessionHi(), keys.sessionLo());
        return Optional.ofNullable(Session.of(nas, acctSessionId, s));
    }

    /** The active sessions of {@code user} (User-Name, case folded as the cluster does). */
    public List<Session.Active> activeSessions(String user) {
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        long key = UserKeys.user(new UnsafeBuffer(name), 0, name.length);
        List<Session.Active> result = new ArrayList<>();
        for (AdminClient.ListedSession s : admin().userSessions(key)) {
            result.add(new Session.Active(nasName(s.nasId()), s.attribute(44), s.attribute(1)));
        }
        return result;
    }

    private String nasName(int nasId) {
        for (NasClient c : registry.clients()) {
            if (c.id() == nasId) {
                return c.name();
            }
        }
        return Integer.toString(nasId);
    }

    private synchronized AdminClient admin() {
        if (leader() < 0) {
            throw new IllegalStateException("the cluster has no leader (paused, or too few members running)");
        }
        if (admin == null) {
            admin = new AdminClient(memberConfigs[0].members(), memberConfigs[0].basePort());
        }
        return admin;
    }

    // ---- CoA and Disconnect -----------------------------------------------------------------------------------

    /**
     * Sends a Disconnect-Request for every active session of {@code user} to the NAS it is on, through the first
     * RADIUS server's CoA path, and waits for the answers ({@code nas.<name>.coa.port}, or {@link Builder#coaPort}).
     */
    public List<CoaResult> disconnect(String user) {
        return coaResults(coa -> coa.disconnectUser(user));
    }

    /** Sends a CoA-Request with {@code items} (users-file syntax, e.g. {@code "Session-Timeout = 600"}) to every
     * active session of {@code user}. */
    public List<CoaResult> coa(String user, String... items) {
        List<AttributeItem> attributes = new ArrayList<>();
        for (String item : items) {
            attributes.addAll(ItemParser.parse(item, "CoA attribute"));
        }
        return coaResults(coa -> coa.changeUser(user, attributes));
    }

    private interface CoaCall {
        List<CoaService.SessionResult> call(CoaService coa) throws TimeoutException;
    }

    private List<CoaResult> coaResults(CoaCall call) {
        CoaService coa = running(0).coa();
        if (coa == null) {
            throw new IllegalStateException("CoA is off (coa.enabled=false)");
        }
        try {
            List<CoaResult> results = new ArrayList<>();
            for (CoaService.SessionResult r : call.call(coa)) {
                results.add(new CoaResult(
                        r.nas(),
                        r.acctSessionId(),
                        r.user(),
                        CoaResult.Outcome.valueOf(r.outcome().name()),
                        r.errorCause()));
            }
            return results;
        } catch (TimeoutException e) {
            throw new IllegalStateException("the cluster did not list the user's sessions in time", e);
        }
    }

    // ---- the cluster ------------------------------------------------------------------------------------------

    /** The index of the member that leads, or -1 without a leader. */
    public synchronized int leader() {
        for (int i = 0; i < members.length; i++) {
            if (members[i] != null && "LEADER".equals(members[i].stats().role())) {
                return i;
            }
        }
        return -1;
    }

    /** Waits for a leader among the running members and returns its index. */
    public int awaitLeader() {
        await(START_TIMEOUT, "a leader", () -> leader() >= 0);
        return leader();
    }

    /**
     * Stops member {@code i} (it closes, as a member that is shut down; a crash is what the process-based tests
     * cover). With three members, the other two go on; with fewer than a majority, nothing is acknowledged until one
     * is back.
     */
    public synchronized void stopMember(int i) {
        if (members[i] == null) {
            return;
        }
        if (admin != null) {
            CloseHelper.quietClose(admin);
            admin = null;
        }
        CloseHelper.close(members[i]);
        members[i] = null;
    }

    /** Starts member {@code i} again from its files; it catches up from the others. */
    public synchronized void startMember(int i) {
        if (members[i] == null) {
            members[i] = ClusterNode.launch(memberConfigs[i], null);
        }
    }

    /** Stops the member that leads and returns its index; the others elect a new leader. */
    public int stopLeader() {
        int leader = awaitLeader();
        stopMember(leader);
        return leader;
    }

    /**
     * Stops every member: Accounting-Requests get no Accounting-Response (the NAS has to keep and resend them), and
     * logins that need the cluster (Simultaneous-Use, SIM sequence numbers) are not answered.
     */
    public synchronized void pauseCluster() {
        for (int i = 0; i < members.length; i++) {
            stopMember(i);
        }
        await(
                START_TIMEOUT,
                "the RADIUS servers noticed",
                () -> runningServers().noneMatch(s -> s.stats().connected()));
    }

    /** Starts every stopped member again from its files; what the NAS resends is applied once. */
    public void resumeCluster() {
        synchronized (this) {
            for (int i = 0; i < members.length; i++) {
                startMember(i);
            }
        }
        awaitLeader();
        awaitServersConnected();
    }

    /** Whether no member runs. */
    public synchronized boolean paused() {
        return Stream.of(members).allMatch(Objects::isNull);
    }

    /** Stops RADIUS server {@code i}: its ports stop answering, as when a server goes away behind a NAS. */
    public synchronized void stopServer(int i) {
        CloseHelper.quietClose(servers[i]);
        servers[i] = null;
    }

    /** Starts RADIUS server {@code i} again on the ports it had. */
    public void startServer(int i) {
        synchronized (this) {
            if (servers[i] != null) {
                return;
            }
            servers[i] = launchServer(serverConfigs[i]);
        }
        await(
                START_TIMEOUT,
                "RADIUS server " + i + " connected",
                () -> running(i).stats().connected());
    }

    private Stream<RadiusServer> runningServers() {
        synchronized (this) {
            return Stream.of(servers.clone()).filter(Objects::nonNull);
        }
    }

    private void awaitServersConnected() {
        await(
                START_TIMEOUT,
                "the RADIUS servers connected",
                () -> runningServers().allMatch(s -> s.stats().connected()));
    }

    private RadiusServer launchServer(Config c) {
        ServerConfig serverConfig = ServerConfig.from(c);
        AuthConfig auth = AuthConfig.from(c);
        RadiusServer server = RadiusServer.builder(serverConfig, registry)
                .auth(auth)
                .handlerFactory(auth.enabled() ? RadiusServer.storeHandler(c, auth, plugins) : dictionary -> null)
                .radsec(RadsecConfig.from(c, serverConfig.listenHost()))
                .coa(CoaConfig.from(c))
                .proxy(ProxyConfig.from(c))
                .start();
        server.rejectDelay(RadiusServer.rejectDelay(c));
        return server;
    }

    private void start() {
        for (int i = 0; i < members.length; i++) {
            startMember(i);
        }
        awaitLeader();
        for (int i = 0; i < servers.length; i++) {
            servers[i] = launchServer(serverConfigs[i]);
            // a restart takes the same ports, so a NAS keeps sending to the server it knows
            serverConfigs[i] = serverConfigs[i].with(Map.of(
                    "server.listen.port", Integer.toString(servers[i].radiusPort()),
                    "server.auth.port", Integer.toString(servers[i].authPort())));
        }
        awaitServersConnected();
        // the newest state version (Simultaneous-Use, session identities, SIM sequence numbers) from the start: the
        // members report what they support every log.purge.interval and the cluster activates it (ADR 0005)
        int newest = memberConfigs[0].serviceSettings().supportedVersion();
        await(
                START_TIMEOUT,
                "state version " + newest + " active",
                () -> admin().state().activeVersion() >= newest);
        LOG.warn(
                "embedded radiusward for development and tests, NOT for production: {} member(s) on one machine,"
                        + " nothing synced to disk; Access-Requests on {}:{}, Accounting-Requests on {}:{}, files in {}",
                members.length,
                host,
                authPort(),
                host,
                accountingPort(),
                directory);
    }

    @Override
    public synchronized void close() {
        CloseHelper.quietClose(admin);
        admin = null;
        for (int i = 0; i < servers.length; i++) {
            CloseHelper.quietClose(servers[i]);
            servers[i] = null;
        }
        for (int i = 0; i < members.length; i++) {
            CloseHelper.quietClose(members[i]);
            members[i] = null;
        }
        owned.forEach(CloseHelper::quietClose);
        if (deleteDirectory) {
            delete(directory);
        }
    }

    /**
     * A new directory only this user can read and write ({@code rwx------} where the file system has POSIX permissions,
     * owner-only access flags elsewhere): other users of the machine must not read the member's files or put their own
     * there.
     */
    static Path temporaryDirectory() throws IOException {
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempDirectory(
                    "radiusward-embedded",
                    java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        }
        java.io.File dir = Files.createTempDirectory("radiusward-embedded").toFile();
        // without POSIX permissions (Windows, where the temporary folder is the user's own): access for its owner
        boolean readable = dir.setReadable(true, true);
        boolean writable = dir.setWritable(true, true);
        boolean listable = dir.setExecutable(true, true);
        if (!readable || !writable || !listable) {
            LOG.warn("could not restrict {} to its owner", dir);
        }
        return dir.toPath();
    }

    private static void delete(Path dir) {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> files = Files.walk(dir)) {
            files.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException e) {
            LOG.warn("could not delete {}: {}", dir, e.toString());
        }
    }

    static void await(Duration timeout, String what, BooleanSupplier condition) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("timed out waiting for " + what);
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("interrupted waiting for " + what, e);
            }
        }
    }

    private static ClusterNodeConfig withExport(ClusterNodeConfig c, ExportConfig export) {
        return new ClusterNodeConfig(
                c.nodeId(),
                c.members(),
                c.basePort(),
                c.dataDir(),
                c.aeronDir(),
                c.profile(),
                c.leaderHeartbeatTimeout(),
                c.electionTimeout(),
                c.sessionTimeout(),
                c.snapshotInterval(),
                c.fileSyncLevel(),
                c.diskMinFree(),
                c.maxClientSessions(),
                c.serviceSettings(),
                c.sweepInterval(),
                export,
                c.purge(),
                c.versionHold());
    }

    /** Fails with the option to add when Agrona and Aeron cannot reach {@code jdk.internal.misc}. */
    static void checkJvmOption() {
        Module base = Object.class.getModule();
        if (!base.isExported("jdk.internal.misc", EmbeddedRadiusward.class.getModule())) {
            throw new IllegalStateException("embedded radiusward needs the JVM option " + JVM_OPTION
                    + " (Agrona and Aeron use jdk.internal.misc): add it to Surefire's and Failsafe's argLine, Gradle's"
                    + " jvmArgs or the IDE's run configuration");
        }
    }

    /** What to start; {@link #start()} starts it. Every method may be called several times. */
    public static final class Builder {

        final Map<String, String> settings = new LinkedHashMap<>();
        final Map<String, String[]> nas = new LinkedHashMap<>();
        final Map<String, UserRecord> users = new LinkedHashMap<>();
        final List<IdentityStore> stores = new ArrayList<>();
        final List<CredentialVerifier> verifiers = new ArrayList<>();
        final Map<String, AccountingSink> sinks = new LinkedHashMap<>();
        final RecordingSink recorder = new RecordingSink();
        final List<String> eap = new ArrayList<>();
        Map<String, String> generated = Map.of();
        Path directory;
        int authPort;
        int accountingPort;
        int coaPort;
        int members = 1;
        int radiusServers = 1;

        private Builder() {}

        /** Keeps the files in {@code directory} (kept after close); by default a temporary one, deleted on close. */
        public Builder directory(Path directory) {
            this.directory = Objects.requireNonNull(directory);
            return this;
        }

        /**
         * How many cluster members (1 by default): 3 or 5 to test what a NAS or an application sees when a member
         * stops ({@link EmbeddedRadiusward#stopMember}, {@link EmbeddedRadiusward#stopLeader}). An even number is
         * refused: two members survive no failure, four no more than three.
         */
        public Builder members(int members) {
            if (members < 1 || members > 7 || members % 2 == 0) {
                throw new IllegalArgumentException("members: 1, 3, 5 or 7, got " + members);
            }
            this.members = members;
            return this;
        }

        /** How many RADIUS servers (1 by default), each with its own ports ({@link EmbeddedRadiusward#authPort(int)}). */
        public Builder radiusServers(int radiusServers) {
            if (radiusServers < 1 || radiusServers > 8) {
                throw new IllegalArgumentException("radiusServers: 1 to 8, got " + radiusServers);
            }
            this.radiusServers = radiusServers;
            return this;
        }

        /** The first RADIUS server's port for Access-Requests; by default a free one. */
        public Builder authPort(int port) {
            this.authPort = port;
            return this;
        }

        /** The first RADIUS server's port for Accounting-Requests; by default a free one. */
        public Builder accountingPort(int port) {
            this.accountingPort = port;
            return this;
        }

        /**
         * Where the NAS entries listen for CoA and Disconnect-Requests ({@code nas.<name>.coa.port}, 3799 otherwise),
         * e.g. a {@code CoaListener}'s port.
         */
        public Builder coaPort(int port) {
            this.coaPort = port;
            return this;
        }

        /**
         * A NAS entry: requests from {@code address} (an address or a network, e.g. {@code 10.0.0.0/8}) with this
         * secret. Without any, {@value #DEFAULT_NAS} is 127.0.0.1 with {@value #DEFAULT_SECRET}.
         */
        public Builder client(String address, String secret) {
            return client("nas-" + (nas.size() + 1), address, secret);
        }

        /** A NAS entry with a name ({@code nas.<name>.*} settings refine it). */
        public Builder client(String name, String address, String secret) {
            nas.put(name, new String[] {address, secret});
            return this;
        }

        /**
         * A user with a password, and reply items in the users-file syntax, e.g. {@code "Class := gold"}, {@code
         * "Session-Timeout = 3600"}. PAP, CHAP, MS-CHAP and every EAP method that needs a password work with it.
         */
        public Builder user(String name, String password, String... replyItems) {
            return user(name, List.of(new AttributeItem("Cleartext-Password", ":=", password)), replyItems);
        }

        /**
         * A SIM subscriber for EAP-SIM, EAP-AKA and EAP-AKA′ ({@code eap("sim", "aka", "aka-prime")}): its IMSI, the
         * key Ki and the operator's OPc (16 bytes each, as the SIM card holds them); sequence numbers come from the
         * cluster as in production.
         */
        public Builder simUser(String imsi, byte[] ki, byte[] opc, String... replyItems) {
            if (ki.length != 16 || opc.length != 16) {
                throw new IllegalArgumentException("Ki and OPc are 16 bytes each");
            }
            HexFormat hex = HexFormat.of();
            return user(
                    imsi,
                    List.of(
                            new AttributeItem("SIM-Ki", ":=", "0x" + hex.formatHex(ki)),
                            new AttributeItem("SIM-OPc", ":=", "0x" + hex.formatHex(opc))),
                    replyItems);
        }

        private Builder user(String name, List<AttributeItem> check, String... replyItems) {
            List<AttributeItem> reply = new ArrayList<>();
            for (String item : replyItems) {
                reply.addAll(ItemParser.parse(item, "reply item of " + name));
            }
            users.put(name.toLowerCase(Locale.ROOT), new UserRecord(name, check, reply, List.of()));
            return this;
        }

        /**
         * EAP methods to offer, in order of preference ({@code auth.eap.methods}): {@code tls}, {@code peap}, {@code
         * ttls}, {@code teap}, {@code pwd}, {@code sim}, {@code aka}, {@code aka-prime}, {@code md5}. With a TLS-based
         * one and no certificate of your own, a throwaway CA signs the server's certificate ({@link
         * EmbeddedRadiusward#ca()}).
         */
        public Builder eap(String... methods) {
            for (String m : methods) {
                eap.add(m.trim().toLowerCase(Locale.ROOT));
            }
            return this;
        }

        /**
         * The developer's own identity store (auth-api): asked after the users of {@link #user} and the stores added
         * before it. radiusward still checks the password, the check items and EAP, and sends the reply items.
         */
        public Builder identityStore(IdentityStore store) {
            stores.add(Objects.requireNonNull(store));
            return this;
        }

        /** An identity store as a function: the user, or empty if unknown. */
        public Builder users(Function<String, Optional<UserRecord>> lookup) {
            Objects.requireNonNull(lookup);
            return identityStore(new IdentityStore() {
                @Override
                public Optional<UserRecord> lookup(String userName) {
                    return lookup.apply(userName);
                }

                @Override
                public void close() {}
            });
        }

        /**
         * The developer's own credential verifier (auth-api): checks the passwords of the users of the identity stores
         * given here that hold none of their own (as an LDAP bind or a domain controller does).
         */
        public Builder credentialVerifier(CredentialVerifier verifier) {
            if (!verifiers.isEmpty()) {
                throw new IllegalStateException("one credential verifier only");
            }
            verifiers.add(Objects.requireNonNull(verifier));
            return this;
        }

        /**
         * The developer's own sink (export-api): gets every committed batch with the contract production sinks have
         * (at least once, in commit order; its stored position decides where it resumes). With several members, the
         * one that holds the sink's lease writes, as in production.
         */
        public Builder sink(AccountingSink sink) {
            return sink("sink-" + (sinks.size() + 1), sink);
        }

        /** A sink with a name ({@code sink.<name>.*} settings refine it, e.g. {@code mode}). */
        public Builder sink(String name, AccountingSink sink) {
            sinks.put(name, Objects.requireNonNull(sink));
            return this;
        }

        /** Called with every committed accounting event, in commit order, on the exporter's thread. */
        public Builder onAccounting(Consumer<ExportEvent> listener) {
            recorder.listen(Objects.requireNonNull(listener));
            return this;
        }

        /** Any key of the configuration reference; it overrides what the builder's other methods set. */
        public Builder setting(String key, String value) {
            settings.put(key, value);
            return this;
        }

        /**
         * Starts the members and the RADIUS servers; returns once a member leads, every RADIUS server is connected and
         * the newest state version is active.
         */
        public EmbeddedRadiusward start() {
            checkJvmOption();
            // as the server's main does: TLS sessions the server keeps, so EAP resumption works and is checked again
            if (System.getProperty("jdk.tls.server.enableSessionTicketExtension") == null) {
                System.setProperty("jdk.tls.server.enableSessionTicketExtension", "false");
            }
            boolean temporary = directory == null;
            Path dir;
            try {
                dir = temporary ? temporaryDirectory() : Files.createDirectories(directory);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            int basePort = Ports.reserveBase(members);
            EmbeddedRadiusward radius = null;
            try {
                ThrowawayPki pki = needsPki() ? ThrowawayPki.create(dir.resolve("pki")) : null;
                generated = pki == null ? Map.of() : pki.settings();
                radius = new EmbeddedRadiusward(this, Config.of(values(dir, basePort)), dir, temporary, pki);
                radius.start();
                return radius;
            } catch (RuntimeException | Error e) {
                if (radius != null) {
                    radius.close();
                } else if (temporary) {
                    delete(dir);
                }
                throw e;
            } finally {
                Ports.release(basePort);
            }
        }

        /** The settings this builder starts with (tests); {@link EmbeddedSettings#values}. */
        Map<String, String> values(Path dir, int basePort) {
            return EmbeddedSettings.values(this, dir, basePort);
        }

        private boolean needsPki() {
            return eap.stream().anyMatch(TLS_METHODS::contains) && !settings.containsKey("auth.eap.tls.certificate");
        }
    }
}
