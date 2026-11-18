/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.testing.Await;
import io.radiusward.testing.Ports;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.agrona.concurrent.ShutdownSignalBarrier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code radiusward server} in this JVM, from its configuration files to its shutdown: the management endpoints,
 * SIGHUP and {@code POST /reload}, and the drain before the stop ({@code server.shutdown.drain}).
 */
@Epic("Operations")
@Feature("RADIUS server process")
@DisabledOnOs(OS.WINDOWS) // SIGHUP
class ServerMainIT {

    private static final String RELOAD_TOKEN = "a-token-of-16-chars";

    @TempDir
    Path dir;

    private final ShutdownSignalBarrier barrier = new ShutdownSignalBarrier();
    private final AtomicBoolean exited = new AtomicBoolean();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private Thread server;
    private Object previousHangUp;
    private String statelessTickets;
    private HttpClient http;

    @BeforeEach
    void rememberProcessSettings() throws Exception {
        statelessTickets = System.getProperty(TlsCredentials.STATELESS_TICKETS);
        previousHangUp = handleHangUp(signalHandler("SIG_DFL"));
        handleHangUp(previousHangUp);
        http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    @AfterEach
    void stop() throws Exception {
        barrier.signal();
        if (server != null) {
            server.interrupt(); // cuts a drain short
            server.join(30_000);
        }
        barrier.close();
        http.close();
        handleHangUp(previousHangUp);
        if (statelessTickets == null) {
            System.clearProperty(TlsCredentials.STATELESS_TICKETS);
        } else {
            System.setProperty(TlsCredentials.STATELESS_TICKETS, statelessTickets);
        }
    }

    @Test
    void servesReloadsAndDrainsBeforeItStops() throws Exception {
        int authPort = Ports.freePort();
        int managementPort = Ports.freePort();
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Path serverFile = Files.writeString(
                dir.resolve("server.properties"),
                String.join(
                        "\n",
                        "server.listen.host=127.0.0.1",
                        "server.listen.port=0",
                        "server.auth.enabled=true",
                        "server.auth.port=" + authPort,
                        "server.aeron.dir=" + dir.resolve("aeron"),
                        "server.shutdown.drain=60s",
                        "cluster.members=localhost",
                        "cluster.base.port=" + Ports.freePortBase(1),
                        "auth.stores=local",
                        "auth.store.local.type=file",
                        "auth.store.local.path=" + users,
                        "auth.plugins.dir=" + dir.resolve("no-plugins"),
                        "management.http.host=127.0.0.1",
                        "management.http.port=" + managementPort,
                        "reload.api.token=" + RELOAD_TOKEN,
                        "trace.api.token=a-trace-token-of-16",
                        "coa.enabled=true",
                        "coa.api.token=a-coa-token-of-16-chars",
                        ""));
        Path nasFile = Files.writeString(
                dir.resolve("nas-clients.properties"),
                "nas.local.address=127.0.0.1\nnas.local.secret="
                        + new String(AuthAgentTest.SECRET, StandardCharsets.US_ASCII) + "\n");

        start(serverFile, nasFile);
        String base = "http://127.0.0.1:" + managementPort;
        // /reload is added after the SIGHUP handler: once it answers, both are in place
        Await.until(Duration.ofSeconds(30), "the reload endpoint", () -> status("POST", base + "/reload", null) == 401);
        assertThat(failure.get()).isNull();

        assertThat(get(base + "/health").statusCode()).isEqualTo(200);
        HttpResponse<String> ready = get(base + "/ready");
        assertThat(ready.statusCode()).as("no cluster to reach").isEqualTo(503);
        assertThat(get(base + "/state").statusCode()).isEqualTo(200);
        assertThat(get(base + "/metrics").statusCode()).isEqualTo(200);
        assertThat(status("GET", base + "/trace", null))
                .as("trace API, token required")
                .isEqualTo(401);
        assertThat(status("GET", base + "/coa/sessions", null))
                .as("CoA API, token required")
                .isEqualTo(401);

        byte[] request = AuthAgentTest.accessRequest(1, "arctangent", true, false);
        AuthAgentTest.assertSignedReplyTo(exchange(request, authPort), request, RadiusCode.ACCESS_ACCEPT);

        // SIGHUP: another password from the users file
        Files.writeString(users, "nemo    Cleartext-Password := \"changed\"\n");
        raiseHangUp();
        int[] identifier = {10};
        Await.until(
                Duration.ofSeconds(10),
                "the users file reloaded on SIGHUP",
                () -> accepts("changed", authPort, identifier[0]++));

        // SIGHUP with a configuration that does not load: the running one stays
        Files.writeString(serverFile, "auth.totp.mode=carrier-pigeon\n", java.nio.file.StandardOpenOption.APPEND);
        raiseHangUp();
        Thread.sleep(300);
        assertThat(accepts("changed", authPort, 40)).isTrue();
        assertThat(server.isAlive()).isTrue();

        // and the same through POST /reload, which reports the failure
        assertThat(status("POST", base + "/reload", "Bearer " + RELOAD_TOKEN)).isEqualTo(400);

        Object installed = handleHangUp(previousHangUp);
        assertThat(installed.toString()).isEqualTo("SIGHUP reload");
        assertThat(installed.equals(installed)).isTrue();
        assertThat(installed.equals(previousHangUp)).isFalse();
        assertThat(installed.hashCode()).isEqualTo(System.identityHashCode(installed));

        // SIGTERM: not ready while draining, still answering; an interrupt cuts the long drain short
        barrier.signal();
        Await.until(Duration.ofSeconds(10), "draining", () -> {
            try {
                HttpResponse<String> r = get(base + "/ready");
                return r.statusCode() == 503 && r.body().contains("draining before shutdown");
            } catch (Exception e) {
                return false;
            }
        });
        assertThat(get(base + "/health").statusCode()).isEqualTo(200);
        assertThat(accepts("changed", authPort, 41))
                .as("answers while draining")
                .isTrue();
        assertThat(exited).isFalse();
        server.interrupt();
        server.join(20_000);
        assertThat(server.isAlive())
                .as("stopped long before the 1 minute drain")
                .isFalse();
        assertThat(failure.get()).isNull();
        assertThat(exited).isTrue();
        assertThat(status("GET", base + "/health", null))
                .as("management server closed")
                .isEqualTo(-1);
    }

    /** Runs the command on a thread of its own, as {@code radiusward server --config ... --config ...}. */
    private void start(Path... files) {
        String[] args = new String[files.length * 2];
        for (int i = 0; i < files.length; i++) {
            args[2 * i] = "--config";
            args[2 * i + 1] = files[i].toString();
        }
        server = new Thread(
                () -> {
                    try {
                        ServerMain.run(args, () -> barrier, () -> exited.set(true));
                    } catch (Throwable t) {
                        failure.set(t);
                    }
                },
                "radiusward-server-main");
        server.start();
    }

    @Test
    void withoutManagementServerOrTokensItStillServesAndStopsAfterItsDrain() throws Exception {
        int authPort = Ports.freePort();
        Path users = Files.writeString(dir.resolve("users"), "nemo    Cleartext-Password := \"arctangent\"\n");
        Path serverFile = Files.writeString(
                dir.resolve("server.properties"),
                String.join(
                        "\n",
                        "server.listen.host=127.0.0.1",
                        "server.listen.port=0",
                        "server.auth.enabled=true",
                        "server.auth.port=" + authPort,
                        "server.aeron.dir=" + dir.resolve("aeron"),
                        "server.shutdown.drain=300ms",
                        "cluster.members=localhost",
                        "cluster.base.port=" + Ports.freePortBase(1),
                        "auth.stores=local",
                        "auth.store.local.type=file",
                        "auth.store.local.path=" + users,
                        "auth.plugins.dir=" + dir.resolve("no-plugins"),
                        "management.http.enabled=false",
                        "nas.local.address=127.0.0.1",
                        "nas.local.secret=" + new String(AuthAgentTest.SECRET, StandardCharsets.US_ASCII),
                        ""));
        start(serverFile);
        int[] identifier = {1};
        Await.until(Duration.ofSeconds(30), "Access-Accept", () -> accepts("arctangent", authPort, identifier[0]++));
        assertThat(failure.get()).isNull();

        long stopping = System.nanoTime();
        barrier.signal();
        server.join(20_000);
        assertThat(server.isAlive()).isFalse();
        assertThat(System.nanoTime() - stopping).as("drained first").isGreaterThanOrEqualTo(300_000_000L);
        assertThat(failure.get()).isNull();
        assertThat(exited).isTrue();
    }

    private boolean accepts(String password, int authPort, int identifier) {
        try {
            byte[] reply = exchange(AuthAgentTest.accessRequest(identifier & 0xFF, password, true, false), authPort);
            return reply[0] == (byte) RadiusCode.ACCESS_ACCEPT;
        } catch (Exception e) {
            return false;
        }
    }

    private HttpResponse<String> get(String uri) throws Exception {
        return http.send(
                HttpRequest.newBuilder(URI.create(uri))
                        .timeout(Duration.ofSeconds(5))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** The status of a request, -1 when nothing answers. */
    private int status(String method, String uri, String authorization) {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(uri))
                .timeout(Duration.ofSeconds(5))
                .method(method, HttpRequest.BodyPublishers.noBody());
        if (authorization != null) {
            request.header("Authorization", authorization);
        }
        try {
            return http.send(request.build(), HttpResponse.BodyHandlers.discarding())
                    .statusCode();
        } catch (java.io.IOException e) {
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    private static byte[] exchange(byte[] request, int port) throws Exception {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        try (DatagramSocket nas = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            nas.setSoTimeout(3_000);
            nas.send(new DatagramPacket(request, request.length, loopback, port));
            byte[] in = new byte[4096];
            DatagramPacket p = new DatagramPacket(in, in.length);
            nas.receive(p);
            return Arrays.copyOf(in, p.getLength());
        }
    }

    // sun.misc.Signal through reflection, as the server itself uses it

    private static Object hangUp() throws ReflectiveOperationException {
        return Class.forName("sun.misc.Signal").getConstructor(String.class).newInstance("HUP");
    }

    private static Object signalHandler(String field) throws ReflectiveOperationException {
        return Class.forName("sun.misc.SignalHandler").getField(field).get(null);
    }

    /** Installs {@code handler} for SIGHUP and returns the one it replaces. */
    private static Object handleHangUp(Object handler) throws ReflectiveOperationException {
        Class<?> signal = Class.forName("sun.misc.Signal");
        Class<?> handlerType = Class.forName("sun.misc.SignalHandler");
        return signal.getMethod("handle", signal, handlerType).invoke(null, hangUp(), handler);
    }

    private static void raiseHangUp() throws ReflectiveOperationException {
        Class<?> signal = Class.forName("sun.misc.Signal");
        signal.getMethod("raise", signal).invoke(null, hangUp());
    }
}
