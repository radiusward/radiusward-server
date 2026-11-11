/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.Capability;
import com.github.dockerjava.api.model.Device;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

/**
 * Three cluster members, two gateways and a tools container in one Docker network with the static addresses
 * and configuration files of {@code deploy/compose}, so the shipped configuration is what gets tested.
 *
 * <p>Everything that talks to the containers runs inside the network, from the tools container: on macOS the
 * host cannot reach container addresses, and published UDP ports rewrite the NAS source address.
 *
 * <p>Members use the test image (LazyFS, iptables, root); gateways and tools the release image.
 */
final class ContainerCluster implements AutoCloseable {

    static final String IMAGE = System.getProperty("radiusward.image", "radiusward:dev");
    static final String TEST_IMAGE = System.getProperty("radiusward.test.image", "radiusward-test:dev");
    static final Path COMPOSE_DIR = Path.of(System.getProperty("radiusward.compose.dir", "../../deploy/compose"));
    static final String SECRET = "testing123";
    static final int NAS_ID = 1001;
    static final String MEMBERS = "172.28.0.10,172.28.0.11,172.28.0.12";
    static final String GATEWAYS = "172.28.0.20:1813,172.28.0.21:1813";
    static final String TOOLS_IP = "172.28.0.30";
    private static final long MIB = 1024L * 1024;
    private static final Pattern ROLE = Pattern.compile("\"role\":\"(\\w+)\"");
    private static final Pattern NUMBER_FIELD = Pattern.compile("\"(\\w+)\":(-?\\d+)");
    private static final Pattern STRING_FIELD = Pattern.compile("\"(\\w+)\":\"([^\"]*)\"");

    /** What differs between tests. */
    record Options(
            int fileSyncLevel,
            boolean lazyFs,
            long nodeMemoryMib,
            long gatewayMemoryMib,
            long dataTmpfsMib,
            boolean postgres,
            Map<String, String> nodeEnv) {
        static Options defaults() {
            return new Options(2, false, 1024, 384, 0, false, Map.of());
        }

        Options fileSyncLevel(int level) {
            return new Options(level, lazyFs, nodeMemoryMib, gatewayMemoryMib, dataTmpfsMib, postgres, nodeEnv);
        }

        Options lazyFs(boolean on) {
            return new Options(fileSyncLevel, on, nodeMemoryMib, gatewayMemoryMib, dataTmpfsMib, postgres, nodeEnv);
        }

        /** Data directory on a tmpfs of this size (0: the image volume), to run out of disk space. */
        Options dataTmpfsMib(long mib) {
            return new Options(fileSyncLevel, lazyFs, nodeMemoryMib, gatewayMemoryMib, mib, postgres, nodeEnv);
        }

        Options memoryMib(long node, long gateway) {
            return new Options(fileSyncLevel, lazyFs, node, gateway, dataTmpfsMib, postgres, nodeEnv);
        }

        /** PostgreSQL at the compose address with the compose sink {@code pg} enabled on the members. */
        Options postgres(boolean on) {
            return new Options(fileSyncLevel, lazyFs, nodeMemoryMib, gatewayMemoryMib, dataTmpfsMib, on, nodeEnv);
        }

        /** An extra environment variable for every member, e.g. {@code RADIUSWARD_SINK_PG_MAX_LAG=30s}. */
        Options env(String name, String value) {
            Map<String, String> env = new LinkedHashMap<>(nodeEnv);
            env.put(name, value);
            return new Options(
                    fileSyncLevel, lazyFs, nodeMemoryMib, gatewayMemoryMib, dataTmpfsMib, postgres, Map.copyOf(env));
        }
    }

    /** A member or gateway as seen from inside the network. */
    record Member(String name, String ip, GenericContainer<?> container) {}

    private final String testName;
    private final Options options;
    private final DockerClient docker = DockerClientFactory.instance().client();
    private final Network network;
    private final List<Member> nodes = new ArrayList<>();
    private final List<Member> gateways = new ArrayList<>();
    private final GenericContainer<?> tools;
    private final GenericContainer<?> postgres;
    static final String POSTGRES_IP = "172.28.0.40";
    static final String JDBC_URL = "jdbc:postgresql://" + POSTGRES_IP + ":5432/radius";

    /** Where clusters closed during the current test saved their logs, for {@link FailureLogs}. */
    static final List<Path> savedLogs = new java.util.concurrent.CopyOnWriteArrayList<>();

    ContainerCluster(String testName, Options options) {
        this.testName = testName;
        this.options = options;
        network = Network.builder()
                .createNetworkCmdModifier(cmd -> cmd.withIpam(new com.github.dockerjava.api.model.Network.Ipam()
                        .withConfig(
                                new com.github.dockerjava.api.model.Network.Ipam.Config().withSubnet("172.28.0.0/24"))))
                .build();
        tools = new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withNetwork(network)
                .withCreateContainerCmdModifier(cmd ->
                        cmd.withIpv4Address(TOOLS_IP).withHostName("tools").withEntrypoint("sleep", "infinity"));
        postgres = options.postgres()
                ? new GenericContainer<>(DockerImageName.parse("postgres:17-alpine"))
                        .withNetwork(network)
                        .withEnv("POSTGRES_DB", "radius")
                        .withEnv("POSTGRES_USER", "radiusward")
                        .withEnv("POSTGRES_PASSWORD", "radiusward")
                        .withCreateContainerCmdModifier(
                                cmd -> cmd.withIpv4Address(POSTGRES_IP).withHostName("postgres"))
                : null;
        for (int i = 0; i < 3; i++) {
            nodes.add(new Member("node-" + i, "172.28.0.1" + i, node(i)));
        }
        for (int i = 0; i < 2; i++) {
            gateways.add(new Member("gateway-" + (char) ('a' + i), "172.28.0.2" + i, gateway(i)));
        }
    }

    private GenericContainer<?> node(int id) {
        String ip = "172.28.0.1" + id;
        GenericContainer<?> c = new GenericContainer<>(DockerImageName.parse(TEST_IMAGE))
                .withNetwork(network)
                .withEnv("RADIUSWARD_PROFILE", "small")
                .withEnv("RADIUSWARD_CLUSTER_NODE_ID", Integer.toString(id))
                .withEnv("RADIUSWARD_ARCHIVE_FILE_SYNC_LEVEL", Integer.toString(options.fileSyncLevel()))
                .withEnv("RADIUSWARD_TEST_LAZYFS", options.lazyFs() ? "1" : "0")
                // the compose configuration exports to its PostgreSQL; tests that want an exporter set it themselves
                .withEnv("RADIUSWARD_EXPORT_SINKS", options.postgres() ? "pg" : "")
                .withEnv(options.nodeEnv())
                // a small tmpfs data directory needs a matching warning threshold (default 1 GiB)
                .withEnv(
                        "RADIUSWARD_CLUSTER_DISK_MIN_FREE",
                        options.dataTmpfsMib() > 0 ? options.dataTmpfsMib() / 4 + "m" : "1g")
                .withCopyToContainer(config("cluster.properties"), "/etc/radiusward/cluster.properties")
                .withCommand("cluster-node", "--config", "/etc/radiusward/cluster.properties")
                .withCreateContainerCmdModifier(cmd -> {
                    cmd.withIpv4Address(ip).withHostName("node-" + id);
                    cmd.getHostConfig()
                            .withShmSize(512 * MIB)
                            .withMemory(options.nodeMemoryMib() * MIB)
                            .withMemorySwap(options.nodeMemoryMib() * MIB)
                            .withNanoCPUs(1_000_000_000L)
                            .withCapAdd(Capability.NET_ADMIN);
                    if (options.lazyFs()) {
                        cmd.getHostConfig()
                                .withPrivileged(true)
                                .withDevices(new Device("rwm", "/dev/fuse", "/dev/fuse"));
                    }
                    if (options.dataTmpfsMib() > 0) {
                        cmd.getHostConfig()
                                .withTmpFs(Map.of("/var/lib/radiusward", "rw,size=" + options.dataTmpfsMib() + "m"));
                    }
                });
        return c;
    }

    private GenericContainer<?> gateway(int index) {
        String ip = "172.28.0.2" + index;
        return new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withNetwork(network)
                .withEnv("RADIUSWARD_PROFILE", "small")
                .withEnv("RADIUSWARD_GATEWAY_ID", Integer.toString(index + 1))
                .withEnv("RADIUSWARD_GATEWAY_EGRESS_HOST", ip)
                .withEnv("NAS_SECRET", SECRET)
                .withCopyToContainer(config("gateway.properties"), "/etc/radiusward/gateway.properties")
                .withCopyToContainer(config("nas-clients.properties"), "/etc/radiusward/nas-clients.properties")
                // gateway.properties enables authentication with the demo users file, as compose mounts it
                .withCopyToContainer(config("users"), "/etc/radiusward/users")
                .withCommand(
                        "gateway",
                        "--config",
                        "/etc/radiusward/gateway.properties",
                        "--config",
                        "/etc/radiusward/nas-clients.properties")
                .withCreateContainerCmdModifier(cmd -> {
                    cmd.withIpv4Address(ip).withHostName("gateway-" + (char) ('a' + index));
                    cmd.getHostConfig()
                            .withShmSize(128 * MIB)
                            .withMemory(options.gatewayMemoryMib() * MIB)
                            .withMemorySwap(options.gatewayMemoryMib() * MIB)
                            .withNanoCPUs(1_000_000_000L);
                });
    }

    private static Transferable config(String file) {
        try {
            return Transferable.of(
                    Files.readAllBytes(COMPOSE_DIR.resolve("config").resolve(file)));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Starts everything and waits until all members and gateways report ready; cleans up if that fails. */
    ContainerCluster start() {
        return Reports.step("start " + nodes.size() + " members and " + gateways.size() + " gateways", this::startAll);
    }

    private ContainerCluster startAll() {
        try {
            tools.start();
            if (postgres != null) {
                postgres.start();
                awaitPostgres(Duration.ofSeconds(60));
            }
            nodes.parallelStream().forEach(n -> n.container().start());
            awaitReady(nodes, Duration.ofSeconds(60));
            gateways.parallelStream().forEach(g -> g.container().start());
            awaitReady(gateways, Duration.ofSeconds(60));
            return this;
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    // ---- PostgreSQL (Options.postgres) -----------------------------------------------------------

    /** Stops the database container (connections refused) without removing it. */
    void stopPostgres() {
        Reports.step("stop PostgreSQL", () -> {
            docker.stopContainerCmd(postgres.getContainerId()).withTimeout(5).exec();
        });
    }

    void startPostgres() {
        Reports.step("start PostgreSQL", () -> {
            docker.startContainerCmd(postgres.getContainerId()).exec();
            awaitPostgres(Duration.ofSeconds(60));
        });
    }

    private void awaitPostgres(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (exec(postgres, "pg_isready", "-U", "radiusward", "-d", "radius").getExitCode() != 0) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("PostgreSQL not ready after " + timeout);
            }
            sleep(250);
        }
    }

    /** One value from {@code psql -tA}. */
    String psql(String sql) {
        ExecResult r = exec(postgres, "psql", "-U", "radiusward", "-d", "radius", "-tAc", sql);
        if (r.getExitCode() != 0) {
            throw new IllegalStateException(sql + ": " + r.getStderr());
        }
        return r.getStdout().trim();
    }

    /** A sink row of {@code radiusward admin sinks}. */
    record SinkRow(String name, long checkpoint, long lagBytes, int owner, long epoch, boolean detached) {}

    Map<String, SinkRow> sinks() {
        ExecResult r = radiusward("admin", "sinks", "--members", MEMBERS, "--egress-host", TOOLS_IP);
        Map<String, SinkRow> rows = new LinkedHashMap<>();
        for (String line : r.getStdout().split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 8 && !f[0].equals("sink") && f[1].matches("\\d+")) {
                rows.put(
                        f[0],
                        new SinkRow(
                                f[0],
                                Long.parseLong(f[1]),
                                Long.parseLong(f[2]),
                                Integer.parseInt(f[3]),
                                Long.parseLong(f[4]),
                                Boolean.parseBoolean(f[6])));
            }
        }
        return rows;
    }

    /** Waits until sink {@code name} has written everything ({@code lag_bytes} 0). */
    void awaitExportCaughtUp(String name, Duration timeout) {
        awaitExportLagBelow(name, 1, timeout);
    }

    /** Waits until sink {@code name} is less than {@code bytes} behind (under continuous load it is rarely 0). */
    void awaitExportLagBelow(String name, long bytes, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            SinkRow row = sinks().get(name);
            if (row != null && row.lagBytes() < bytes) {
                return;
            }
            sleep(1_000);
        }
        throw new IllegalStateException("sink " + name + " did not catch up: " + sinks());
    }

    /** {@code radiusward admin verify-export} against the database and the cluster. */
    ExecResult verifyExport(String ackLog) {
        ExecResult r = radiusward(
                "admin",
                "verify-export",
                "--jdbc-url",
                JDBC_URL,
                "--jdbc-user",
                "radiusward",
                "--jdbc-password",
                "radiusward",
                "--ack-log",
                ackLog,
                "--nas-id",
                Integer.toString(NAS_ID),
                "--members",
                MEMBERS,
                "--egress-host",
                TOOLS_IP);
        System.out.println(r.getStdout() + r.getStderr());
        return r;
    }

    /** {@code /metrics} of a member or gateway. */
    String metrics(Member m) {
        return radiusward("probe", "http://" + m.ip() + ":9090/metrics").getStdout();
    }

    /** Sum of one metric family's samples in a {@code /metrics} text. */
    static double metric(String metrics, String family) {
        double sum = 0;
        for (String line : metrics.split("\n")) {
            if (line.startsWith(family + "{") || line.startsWith(family + " ")) {
                String v = line.substring(line.lastIndexOf(' ') + 1);
                if (!v.equals("NaN")) {
                    sum += Double.parseDouble(v);
                }
            }
        }
        return sum;
    }

    List<Member> nodes() {
        return nodes;
    }

    Member node(String name) {
        return nodes.stream().filter(n -> n.name().equals(name)).findFirst().orElseThrow();
    }

    List<Member> gateways() {
        return gateways;
    }

    /** {@code kill -9} of the container's main process. LazyFS dies with it: unsynced writes are gone. */
    void kill(Member m) {
        Reports.step("kill -9 " + m.name(), () -> {
            docker.killContainerCmd(m.container().getContainerId())
                    .withSignal("KILL")
                    .exec();
        });
    }

    /** Starts a killed container again (same filesystem, same address). */
    void restart(Member m) {
        Reports.step("restart " + m.name(), () -> {
            docker.startContainerCmd(m.container().getContainerId()).exec();
        });
    }

    /** All three members lose power at once, then come back. */
    void powerLoss() {
        Reports.step("power loss of every member", () -> {
            nodes.parallelStream().forEach(this::kill);
            nodes.parallelStream().forEach(this::restart);
        });
    }

    /** Drops all traffic between {@code m} and the given addresses, both directions (iptables in {@code m}). */
    void isolate(Member m, List<String> peers) {
        Reports.step("isolate " + m.name() + " from " + peers, () -> {
            for (String peer : peers) {
                execOrFail(m.container(), "iptables", "-A", "INPUT", "-s", peer, "-j", "DROP");
                execOrFail(m.container(), "iptables", "-A", "OUTPUT", "-d", peer, "-j", "DROP");
            }
        });
    }

    /** Runs {@code sh -c <command>} in a member or gateway container (as root in the test image). */
    ExecResult shell(Member m, String command) {
        return exec(m.container(), "sh", "-c", command);
    }

    void heal(Member m) {
        Reports.step("heal " + m.name(), () -> execOrFail(m.container(), "iptables", "-F"));
    }

    boolean oomKilled(Member m) {
        InspectContainerResponse.ContainerState state = docker.inspectContainerCmd(
                        m.container().getContainerId())
                .exec()
                .getState();
        return Boolean.TRUE.equals(state.getOOMKilled());
    }

    boolean running(Member m) {
        return Boolean.TRUE.equals(docker.inspectContainerCmd(m.container().getContainerId())
                .exec()
                .getState()
                .getRunning());
    }

    /**
     * Memory of a container from its cgroup (v2): {@code anon} (heap, metaspace, native) and {@code shmem}
     * ({@code /dev/shm}: Aeron buffers) cannot be reclaimed; {@code file} is page cache the kernel drops under
     * pressure; {@code peak} is the highest usage including cache since the container started.
     */
    record Memory(long anon, long shmem, long file, long peak, long limit) {
        long unreclaimable() {
            return anon + shmem;
        }

        @Override
        public String toString() {
            return String.format(
                    "anon %d MiB + shmem %d MiB = %d MiB of %d MiB (cache %d MiB, peak incl. cache %d MiB)",
                    anon >> 20, shmem >> 20, unreclaimable() >> 20, limit >> 20, file >> 20, peak >> 20);
        }
    }

    Memory memory(Member m) {
        ExecResult r = shell(
                m,
                "cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.max; "
                        + "grep -E '^(anon|shmem|file) ' /sys/fs/cgroup/memory.stat");
        Map<String, Long> v = new LinkedHashMap<>();
        String[] lines = r.getStdout().trim().split("\n");
        v.put("peak", Long.parseLong(lines[0].trim()));
        v.put("max", lines[1].trim().equals("max") ? Long.MAX_VALUE : Long.parseLong(lines[1].trim()));
        for (int i = 2; i < lines.length; i++) {
            String[] kv = lines[i].trim().split(" ");
            v.put(kv[0], Long.parseLong(kv[1]));
        }
        return new Memory(
                v.getOrDefault("anon", 0L),
                v.getOrDefault("shmem", 0L),
                v.getOrDefault("file", 0L),
                v.get("peak"),
                v.get("max"));
    }

    /** {@code /state} of a member or gateway, or {@code null} if it does not answer. */
    Map<String, String> state(Member m) {
        ExecResult r = radiusward("probe", "http://" + m.ip() + ":9090/state");
        if (r.getExitCode() != 0) {
            return null;
        }
        Map<String, String> fields = new LinkedHashMap<>();
        Matcher s = STRING_FIELD.matcher(r.getStdout());
        while (s.find()) {
            fields.put(s.group(1), s.group(2));
        }
        Matcher n = NUMBER_FIELD.matcher(r.getStdout());
        while (n.find()) {
            fields.put(n.group(1), n.group(2));
        }
        return fields;
    }

    boolean ready(Member m) {
        return radiusward("probe", "http://" + m.ip() + ":9090/ready").getExitCode() == 0;
    }

    void awaitReady(List<Member> members, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        for (Member m : members) {
            while (!ready(m)) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException(m.name() + " not ready after " + timeout);
                }
                sleep(250);
            }
        }
    }

    /** The member that reports itself leader, waiting up to {@code timeout}. */
    Member awaitLeader(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            for (Member n : nodes) {
                String out =
                        radiusward("probe", "http://" + n.ip() + ":9090/state").getStdout();
                Matcher role = ROLE.matcher(out);
                if (role.find() && role.group(1).equals("LEADER")) {
                    return n;
                }
            }
            sleep(200);
        }
        throw new IllegalStateException("no leader after " + timeout);
    }

    /** A leader other than {@code old}, waiting up to {@code timeout} (e.g. after cutting {@code old} off). */
    Member awaitLeaderOtherThan(Member old, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            for (Member n : nodes) {
                Map<String, String> s = n == old ? null : state(n);
                if (s != null && "LEADER".equals(s.get("role"))) {
                    return n;
                }
            }
            sleep(200);
        }
        throw new IllegalStateException("no leader other than " + old.name() + " after " + timeout);
    }

    /** Waits until every member reports the same applied count and state digest. */
    void awaitConverged(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        String last = "";
        while (System.nanoTime() < deadline) {
            List<String> digests = new ArrayList<>();
            for (Member n : nodes) {
                Map<String, String> s = state(n);
                digests.add(s == null ? "down" : s.get("applied") + "/" + s.get("stateDigest"));
            }
            last = digests.toString();
            if (!digests.contains("down") && digests.stream().distinct().count() == 1) {
                return;
            }
            sleep(500);
        }
        throw new IllegalStateException("members did not converge: " + last);
    }

    /** Runs {@code radiusward <args>} in the tools container. */
    ExecResult radiusward(String... args) {
        String[] command = new String[args.length + 1];
        command[0] = "radiusward";
        System.arraycopy(args, 0, command, 1, args.length);
        return exec(tools, command);
    }

    /** {@code radclient load} against both gateways with an acknowledgement log in the tools container. */
    LoadResult load(int nas, int sessions, int rate, Duration duration, String ackLog) {
        return load(nas, sessions, rate, duration, ackLog, 0);
    }

    /** As above, numbering sessions from {@code firstSession} (distinct sessions for consecutive loads). */
    LoadResult load(int nas, int sessions, int rate, Duration duration, String ackLog, int firstSession) {
        return Reports.step(
                "load: " + sessions + " sessions, " + rate + "/s for " + duration.toSeconds() + " s",
                () -> runLoad(nas, sessions, rate, duration, ackLog, firstSession));
    }

    private LoadResult runLoad(int nas, int sessions, int rate, Duration duration, String ackLog, int firstSession) {
        ExecResult r = radiusward(
                "radclient",
                "load",
                "--server",
                GATEWAYS,
                "--secret",
                SECRET,
                "--nas",
                Integer.toString(nas),
                "--sessions",
                Integer.toString(sessions),
                "--rate",
                Integer.toString(rate),
                "--duration",
                duration.toSeconds() + "s",
                "--interim",
                "5s",
                "--retry-other-server",
                "--first-session",
                Integer.toString(firstSession),
                "--ack-log",
                ackLog);
        System.out.println(r.getStdout());
        Reports.attach("radclient load", r.getStdout());
        return LoadResult.parse(r.getStdout());
    }

    /** {@code radiusward admin verify-acks}: every acknowledged event must be in the replicated state. */
    ExecResult verifyAcks(String ackLog) {
        ExecResult r = radiusward(
                "admin",
                "verify-acks",
                "--members",
                MEMBERS,
                "--egress-host",
                TOOLS_IP,
                "--ack-log",
                ackLog,
                "--nas-id",
                Integer.toString(NAS_ID));
        System.out.println(r.getStdout() + r.getStderr());
        return r;
    }

    private static ExecResult exec(GenericContainer<?> c, String... command) {
        try {
            return c.execInContainer(StandardCharsets.UTF_8, command);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static void execOrFail(GenericContainer<?> c, String... command) {
        ExecResult r = exec(c, command);
        if (r.getExitCode() != 0) {
            throw new IllegalStateException(String.join(" ", command) + ": " + r.getStderr());
        }
    }

    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** Saves every container's log under {@code target/container-logs/<test>/}, then removes everything. */
    @Override
    public void close() {
        Path dir = Path.of(System.getProperty("radiusward.logs.dir", "target/container-logs"))
                .resolve(testName);
        savedLogs.add(dir);
        List<Member> all = new ArrayList<>(nodes);
        all.addAll(gateways);
        for (Member m : all) {
            try {
                if (m.container().getContainerId() != null) {
                    Files.createDirectories(dir);
                    Files.writeString(
                            dir.resolve(m.name() + ".log"), m.container().getLogs());
                }
            } catch (IOException | RuntimeException e) {
                System.err.println("could not save the log of " + m.name() + ": " + e);
            }
        }
        all.forEach(m -> m.container().stop());
        tools.stop();
        if (postgres != null) {
            postgres.stop();
        }
        network.close();
    }
}
