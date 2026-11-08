/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import io.radiusward.testing.LocalCluster;
import io.radiusward.tools.admin.AdminClient;
import java.io.File;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Three cluster members and two gateways as separate {@code java -jar radiusward.jar} processes on loopback,
 * each with its own configuration written to a temp directory and free ports. {@link #kill(String)} is a real
 * {@code kill -9}. Logs stay in the temp directory for failed runs.
 */
final class ProcessCluster implements AutoCloseable {

    static final String SECRET = LocalCluster.SECRET;

    private final Path dir;
    private final Path jar;
    private final int basePort;
    private final Map<String, Integer> managementPorts = new LinkedHashMap<>();
    private final Map<String, Integer> radiusPorts = new LinkedHashMap<>();
    private final Map<String, Process> processes = new LinkedHashMap<>();
    private final Map<String, String> extraGatewayConfig = new LinkedHashMap<>();
    private final HttpClient http =
            HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();

    ProcessCluster(Path dir) throws IOException {
        this.dir = dir;
        this.jar = Path.of(System.getProperty("radiusward.jar", "../../distribution/target/radiusward.jar"));
        if (!Files.isRegularFile(jar)) {
            throw new IllegalStateException(
                    "radiusward.jar not found at " + jar.toAbsolutePath() + "; build with -Pe2e");
        }
        this.basePort = LocalCluster.freePortBase(3);
        for (String name : List.of("node-0", "node-1", "node-2", "gateway-a", "gateway-b")) {
            managementPorts.put(name, freeTcpPort());
        }
        radiusPorts.put("gateway-a", freeUdpPort());
        radiusPorts.put("gateway-b", freeUdpPort());
        writeConfig();
    }

    /** Extra properties for one gateway (e.g. debug settings); call before starting it. */
    ProcessCluster gatewayConfig(String gateway, String properties) throws IOException {
        extraGatewayConfig.put(gateway, properties);
        writeConfig();
        return this;
    }

    private void writeConfig() throws IOException {
        Files.writeString(dir.resolve("cluster.properties"), """
                profile=small
                cluster.members=localhost,localhost,localhost
                cluster.base.port=%d
                cluster.data.dir=%s
                cluster.leader.heartbeat.timeout=1500ms
                cluster.election.timeout=500ms
                archive.file.sync.level=2
                snapshot.interval=0
                management.http.host=127.0.0.1
                """.formatted(basePort, dir.resolve("data")));
        for (int i = 0; i < 3; i++) {
            Files.writeString(
                    dir.resolve("node-" + i + ".properties"),
                    "cluster.node.id=" + i + "\nmanagement.http.port=" + managementPorts.get("node-" + i) + "\n"
                            + "cluster.aeron.dir=" + dir.resolve("aeron/node-" + i) + "\n");
        }
        int id = 1;
        for (String g : List.of("gateway-a", "gateway-b")) {
            Files.writeString(dir.resolve(g + ".properties"), """
                    profile=small
                    gateway.id=%d
                    gateway.listen.host=127.0.0.1
                    gateway.listen.port=%d
                    gateway.aeron.dir=%s
                    cluster.members=localhost,localhost,localhost
                    cluster.base.port=%d
                    management.http.host=127.0.0.1
                    management.http.port=%d
                    %s
                    """.formatted(
                            id++,
                            radiusPorts.get(g),
                            dir.resolve("aeron/" + g),
                            basePort,
                            managementPorts.get(g),
                            extraGatewayConfig.getOrDefault(g, "")));
        }
        Files.writeString(dir.resolve("nas-clients.properties"), """
                nas.local.address=127.0.0.1
                nas.local.secret=%s
                nas.local.id=%d
                """.formatted(SECRET, LocalCluster.NAS_ID));
    }

    void startAll() throws Exception {
        for (String name : managementPorts.keySet()) {
            start(name);
        }
        for (String name : managementPorts.keySet()) {
            awaitReady(name);
        }
    }

    void start(String name) throws IOException {
        if (processes.containsKey(name) && processes.get(name).isAlive()) {
            throw new IllegalStateException(name + " already running");
        }
        List<String> command = new ArrayList<>(List.of(
                ProcessHandle.current().info().command().orElse("java"),
                "-Xms256m",
                "-Xmx384m",
                "-XX:+UseG1GC",
                "-jar",
                jar.toAbsolutePath().toString()));
        if (name.startsWith("node-")) {
            command.addAll(List.of(
                    "cluster-node",
                    "--config",
                    dir.resolve("cluster.properties").toString(),
                    "--config",
                    dir.resolve(name + ".properties").toString()));
        } else {
            command.addAll(List.of(
                    "gateway",
                    "--config",
                    dir.resolve(name + ".properties").toString(),
                    "--config",
                    dir.resolve("nas-clients.properties").toString()));
        }
        File log = dir.resolve(name + ".log").toFile();
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(log))
                .start();
        processes.put(name, process);
    }

    /** {@code kill -9}. */
    void kill(String name) throws InterruptedException {
        Process p = processes.remove(name);
        p.destroyForcibly();
        p.waitFor();
    }

    /** Graceful stop (SIGTERM). */
    void stop(String name) throws InterruptedException {
        Process p = processes.remove(name);
        p.destroy();
        if (!p.waitFor(
                java.util.concurrent.TimeUnit.SECONDS.toMillis(15), java.util.concurrent.TimeUnit.MILLISECONDS)) {
            p.destroyForcibly().waitFor();
        }
    }

    boolean running(String name) {
        return processes.containsKey(name) && processes.get(name).isAlive();
    }

    int radiusPort(String gateway) {
        return radiusPorts.get(gateway);
    }

    String state(String name) {
        try {
            HttpResponse<String> r = http.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + managementPorts.get(name) + "/state"))
                            .timeout(Duration.ofSeconds(2))
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            return r.body();
        } catch (Exception e) {
            return "";
        }
    }

    boolean ready(String name) {
        try {
            return http.send(
                                    HttpRequest.newBuilder(URI.create(
                                                    "http://127.0.0.1:" + managementPorts.get(name) + "/ready"))
                                            .timeout(Duration.ofSeconds(2))
                                            .build(),
                                    HttpResponse.BodyHandlers.ofString())
                            .statusCode()
                    == 200;
        } catch (Exception e) {
            return false;
        }
    }

    static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"?([^,\"}]*)").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    static long number(String json, String name) {
        String v = field(json, name);
        return v == null ? -1 : Long.parseLong(v);
    }

    void awaitReady(String name) {
        LocalCluster.await(
                Duration.ofSeconds(60), name + " ready (log " + dir.resolve(name + ".log") + ")", () -> ready(name));
    }

    String awaitLeader() {
        String[] leader = new String[1];
        LocalCluster.await(Duration.ofSeconds(60), "leader", () -> {
            for (String n : List.of("node-0", "node-1", "node-2")) {
                if (running(n) && "LEADER".equals(field(state(n), "role"))) {
                    leader[0] = n;
                    return true;
                }
            }
            return false;
        });
        return leader[0];
    }

    /** Waits until all running members report the same applied count and digest. */
    void awaitConverged() {
        LocalCluster.await(Duration.ofSeconds(60), "replicas converged", () -> {
            String digest = null;
            long applied = -1;
            for (String n : List.of("node-0", "node-1", "node-2")) {
                if (!running(n)) {
                    continue;
                }
                String s = state(n);
                if (digest == null) {
                    digest = field(s, "stateDigest");
                    applied = number(s, "applied");
                } else if (!digest.equals(field(s, "stateDigest")) || applied != number(s, "applied")) {
                    return false;
                }
            }
            return digest != null && applied >= 0;
        });
    }

    AdminClient admin() {
        return new AdminClient(List.of("localhost", "localhost", "localhost"), basePort);
    }

    Path clusterDir(String node) {
        return dir.resolve("data").resolve(node).resolve("cluster");
    }

    Path jar() {
        return jar;
    }

    Path dir() {
        return dir;
    }

    private static int freeTcpPort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private static int freeUdpPort() throws IOException {
        try (DatagramSocket s = new DatagramSocket(0)) {
            return s.getLocalPort();
        }
    }

    @Override
    public void close() {
        for (Process p : processes.values()) {
            p.destroyForcibly();
        }
        for (Process p : processes.values()) {
            try {
                p.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        processes.clear();
    }
}
