/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.CredentialVerifierProvider;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
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
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import org.agrona.CloseHelper;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * radiusward inside this JVM, for development and tests: one cluster member and one RADIUS server, started with the
 * same code and the same settings as in production, with the developer's own identity stores, credential verifiers and
 * sinks; ports chosen at start; everything gone on {@link #close()}. <b>Not for production</b>: one member replicates
 * nothing and nothing is synced to disk.
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

    private final Config config;
    private final Path directory;
    private final boolean deleteDirectory;
    private final ClusterNodeConfig nodeConfig;
    private final NasRegistry registry;
    private final RecordingSink recorder;
    private final List<AutoCloseable> owned;
    private final String host;
    private final String defaultSecret;
    private final String defaultNas;
    private ClusterNode member;
    private RadiusServer server;
    private AdminClient admin;

    private EmbeddedRadiusward(Builder b, Config config, Path directory, boolean deleteDirectory) {
        this.config = config;
        this.directory = directory;
        this.deleteDirectory = deleteDirectory;
        this.recorder = b.recorder;
        this.owned = b.owned();
        this.host = config.string("server.listen.host");
        this.defaultSecret =
                b.nas.isEmpty() ? DEFAULT_SECRET : b.nas.values().iterator().next()[1];
        this.defaultNas =
                b.nas.isEmpty() ? DEFAULT_NAS : b.nas.keySet().iterator().next();
        ClusterNodeConfig fromSettings = ClusterNodeConfig.from(config);
        this.nodeConfig = withExport(fromSettings, fromSettings.export().withProviders(b.sinkProviders()));
        this.registry = NasRegistry.from(config);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** The port that answers Access-Requests. */
    public int authPort() {
        return server.authPort();
    }

    /** The port that answers Accounting-Requests. */
    public int accountingPort() {
        return server.radiusPort();
    }

    /** The address both ports listen on ({@code 127.0.0.1} unless {@code server.listen.host} says otherwise). */
    public String host() {
        return host;
    }

    /** A client of {@link #authPort()} with the first NAS entry's secret; close it after use. */
    public RadiusClient client() {
        return RadiusClient.udp(host, authPort(), defaultSecret);
    }

    /** A client of {@link #accountingPort()} with the first NAS entry's secret; close it after use. */
    public RadiusClient accountingClient() {
        return RadiusClient.udp(host, accountingPort(), defaultSecret);
    }

    /** Where the member and the RADIUS server keep their files. */
    public Path directory() {
        return directory;
    }

    /** The settings it runs with: its defaults, then the builder's. */
    public Config config() {
        return config;
    }

    /** The RADIUS server, for what this class does not offer (statistics, CoA, reload). */
    public RadiusServer server() {
        return server;
    }

    /** The cluster member, {@code null} while paused. */
    public ClusterNode member() {
        return member;
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

    private AdminClient admin() {
        if (member == null) {
            throw new IllegalStateException("the cluster is paused");
        }
        if (admin == null) {
            admin = new AdminClient(nodeConfig.members(), nodeConfig.basePort());
        }
        return admin;
    }

    // ---- the cluster ------------------------------------------------------------------------------------------

    /**
     * Stops the member: Accounting-Requests get no Accounting-Response (the NAS has to keep and resend them), and
     * logins that need the cluster (Simultaneous-Use, SIM sequence numbers) are not answered.
     */
    public synchronized void pauseCluster() {
        if (member == null) {
            return;
        }
        CloseHelper.quietClose(admin);
        admin = null;
        CloseHelper.close(member);
        member = null;
        await(START_TIMEOUT, "the RADIUS server noticed", () -> !server.stats().connected());
    }

    /** Starts the member again from its files; what the NAS resends is applied once. */
    public synchronized void resumeCluster() {
        if (member != null) {
            return;
        }
        startMember();
        await(START_TIMEOUT, "the RADIUS server connected", () -> server.stats().connected());
    }

    public synchronized boolean paused() {
        return member == null;
    }

    private void startMember() {
        member = ClusterNode.launch(nodeConfig, null);
        await(
                START_TIMEOUT,
                "the member leads",
                () -> "LEADER".equals(member.stats().role()));
    }

    private void start(AuthPlugins plugins) {
        startMember();
        ServerConfig serverConfig = ServerConfig.from(config);
        AuthConfig auth = AuthConfig.from(config);
        server = RadiusServer.builder(serverConfig, registry)
                .auth(auth)
                .handlerFactory(auth.enabled() ? RadiusServer.storeHandler(config, auth, plugins) : dictionary -> null)
                .radsec(RadsecConfig.from(config, serverConfig.listenHost()))
                .coa(CoaConfig.from(config))
                .proxy(ProxyConfig.from(config))
                .start();
        server.rejectDelay(RadiusServer.rejectDelay(config));
        await(START_TIMEOUT, "the RADIUS server connected", () -> server.stats().connected());
        // the newest state version (Simultaneous-Use, session identities, SIM sequence numbers) from the start: the
        // member reports what it supports every log.purge.interval and the cluster activates it (ADR 0005)
        int newest = nodeConfig.serviceSettings().supportedVersion();
        await(
                START_TIMEOUT,
                "state version " + newest + " active",
                () -> admin().state().activeVersion() >= newest);
        LOG.warn(
                "embedded radiusward for development and tests, NOT for production: one member, nothing replicated or"
                        + " synced to disk; Access-Requests on {}:{}, Accounting-Requests on {}:{}, files in {}",
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
        CloseHelper.quietClose(server);
        CloseHelper.quietClose(member);
        member = null;
        owned.forEach(CloseHelper::quietClose);
        if (deleteDirectory) {
            delete(directory);
        }
    }

    /**
     * A new directory only this user can read and write ({@code rwx------} where the file system has POSIX permissions;
     * elsewhere the JDK's default, which is the user's own temporary directory): other users of the machine must not
     * read the member's files or put their own there.
     */
    static Path temporaryDirectory() throws IOException {
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempDirectory(
                    "radiusward-embedded",
                    java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
        }
        return Files.createTempDirectory("radiusward-embedded");
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

        private final Map<String, String> settings = new LinkedHashMap<>();
        private final Map<String, String[]> nas = new LinkedHashMap<>();
        private final Map<String, UserRecord> users = new LinkedHashMap<>();
        private final List<IdentityStore> stores = new ArrayList<>();
        private final List<CredentialVerifier> verifiers = new ArrayList<>();
        private final Map<String, AccountingSink> sinks = new LinkedHashMap<>();
        private final RecordingSink recorder = new RecordingSink();
        private Path directory;
        private int authPort;
        private int accountingPort;

        private Builder() {}

        /** Keeps the files in {@code directory} (kept after close); by default a temporary one, deleted on close. */
        public Builder directory(Path directory) {
            this.directory = Objects.requireNonNull(directory);
            return this;
        }

        /** The port for Access-Requests; by default a free one. */
        public Builder authPort(int port) {
            this.authPort = port;
            return this;
        }

        /** The port for Accounting-Requests; by default a free one. */
        public Builder accountingPort(int port) {
            this.accountingPort = port;
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
            List<AttributeItem> reply = new ArrayList<>();
            for (String item : replyItems) {
                reply.addAll(ItemParser.parse(item, "reply item of " + name));
            }
            users.put(
                    name.toLowerCase(java.util.Locale.ROOT),
                    new UserRecord(
                            name, List.of(new AttributeItem("Cleartext-Password", ":=", password)), reply, List.of()));
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
         * (at least once, in commit order; its stored position decides where it resumes).
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

        /** Starts the member and the RADIUS server; returns once the member leads and the RADIUS server is connected. */
        public EmbeddedRadiusward start() {
            checkJvmOption();
            boolean temporary = directory == null;
            Path dir;
            try {
                dir = temporary ? temporaryDirectory() : Files.createDirectories(directory);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            int basePort = Ports.reserveBase();
            EmbeddedRadiusward radius = null;
            try {
                radius = new EmbeddedRadiusward(this, Config.of(values(dir, basePort)), dir, temporary);
                radius.start(plugins());
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

        /** The embedded defaults, then what the builder's methods say, then {@link #setting}s. */
        Map<String, String> values(Path dir, int basePort) {
            Map<String, String> v = new LinkedHashMap<>();
            v.put("profile", "small");
            v.put("cluster.node.id", "0");
            v.put("cluster.members", "localhost");
            v.put("cluster.base.port", Integer.toString(basePort));
            v.put("cluster.data.dir", dir.resolve("data").toString());
            v.put("cluster.aeron.dir", dir.resolve("aeron/member").toString());
            v.put("cluster.disk.min.free", "0");
            v.put("log.purge.interval", "1s"); // the member reports its state version this often
            v.put("archive.file.sync.level", "0"); // nothing to survive: no fsync
            v.put("archive.segment.length", "8m"); // instead of 128 MB preallocated on disk
            v.put("service.max.sessions", "10000");
            v.put("server.id", "1");
            v.put("server.listen.host", "127.0.0.1");
            v.put("server.listen.port", Integer.toString(accountingPort));
            v.put("server.aeron.dir", dir.resolve("aeron/server").toString());
            v.put("server.pending.capacity", "1024");
            v.put("server.auth.enabled", "true");
            v.put("server.auth.port", Integer.toString(authPort));
            v.put("server.auth.workers", "2");
            v.put("auth.reject.delay", "0s"); // tests should not wait a second for every reject
            v.put("auth.plugins.dir", dir.resolve("plugins").toString());
            v.put("export.plugins.dir", dir.resolve("plugins").toString());
            v.put("dictionary.dir", dir.resolve("dictionary.d").toString());
            if (nas.isEmpty()) {
                v.put("nas." + DEFAULT_NAS + ".address", "127.0.0.1");
                v.put("nas." + DEFAULT_NAS + ".secret", DEFAULT_SECRET);
            }
            nas.forEach((name, entry) -> {
                v.put("nas." + name + ".address", entry[0]);
                v.put("nas." + name + ".secret", entry[1]);
            });
            List<String> storeNames = new ArrayList<>();
            if (!users.isEmpty()) {
                storeNames.add("users");
                v.put("auth.store.users.type", "embedded-users");
                v.put("auth.store.users.chap", "true");
                v.put("auth.store.users.mschap", "true");
            }
            for (int i = 0; i < stores.size(); i++) {
                String name = "store-" + (i + 1);
                storeNames.add(name);
                v.put("auth.store." + name + ".type", "embedded-" + name);
                if (!verifiers.isEmpty()) {
                    v.put("auth.store." + name + ".verifier", "verifier");
                }
            }
            if (!verifiers.isEmpty()) {
                v.put("auth.verifiers", "verifier");
                v.put("auth.verifier.verifier.type", "embedded-verifier");
            }
            if (storeNames.isEmpty()) {
                storeNames.add("users"); // no users yet: every login is rejected, as by an empty users file
                v.put("auth.store.users.type", "embedded-users");
            }
            v.put("auth.stores", String.join(", ", storeNames));
            List<String> sinkNames = new ArrayList<>();
            sinkNames.add(RecordingSink.NAME);
            v.put("sink." + RecordingSink.NAME + ".type", RecordingSink.TYPE);
            v.put("sink." + RecordingSink.NAME + ".mode", "sessions+events");
            v.put("sink." + RecordingSink.NAME + ".batch.linger", "20ms");
            sinks.keySet().forEach(name -> {
                sinkNames.add(name);
                v.put("sink." + name + ".type", "embedded-" + name);
                v.put("sink." + name + ".batch.linger", "20ms");
            });
            v.put("export.sinks", String.join(", ", sinkNames));
            v.putAll(settings);
            return v;
        }

        private AuthPlugins plugins() {
            List<IdentityStoreProvider> providers = new ArrayList<>();
            Map<String, UserRecord> byName = Map.copyOf(users);
            providers.add(IdentityStoreProvider.of("embedded-users", context -> new IdentityStore() {
                @Override
                public Optional<UserRecord> lookup(String userName) {
                    return Optional.ofNullable(byName.get(userName.toLowerCase(java.util.Locale.ROOT)));
                }

                @Override
                public void close() {}
            }));
            for (int i = 0; i < stores.size(); i++) {
                IdentityStore store = stores.get(i);
                providers.add(IdentityStoreProvider.of("embedded-store-" + (i + 1), context -> Kept.store(store)));
            }
            List<CredentialVerifierProvider> verifierProviders = new ArrayList<>();
            for (CredentialVerifier verifier : verifiers) {
                verifierProviders.add(
                        CredentialVerifierProvider.of("embedded-verifier", context -> Kept.verifier(verifier)));
            }
            return new AuthPlugins(providers, verifierProviders);
        }

        SinkProvider[] sinkProviders() {
            List<SinkProvider> providers = new ArrayList<>();
            providers.add(SinkProvider.of(RecordingSink.TYPE, () -> recorder));
            sinks.forEach((name, sink) -> providers.add(SinkProvider.of("embedded-" + name, () -> Kept.sink(sink))));
            return providers.toArray(SinkProvider[]::new);
        }

        /** The developer's instances: the server and the exporter close only views of them; we close them once. */
        List<AutoCloseable> owned() {
            List<AutoCloseable> all = new ArrayList<>(stores);
            all.addAll(verifiers);
            all.addAll(sinks.values());
            return all;
        }
    }
}
