/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.radiusward.common.config.Config;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * Management endpoints on the JDK's built-in HTTP server (ADR 0013): {@code /health} (liveness),
 * {@code /ready} (readiness) and {@code /state} (JSON). One worker thread; handlers only read counters
 * that hot-path threads publish, so they can never slow the agents down. No authentication, no secrets,
 * no write operations.
 */
public final class ManagementServer implements AutoCloseable {

    private final HttpServer server;
    private final ExecutorService executor;

    private ManagementServer(HttpServer server, ExecutorService executor) {
        this.server = server;
        this.executor = executor;
    }

    /**
     * Starts the server.
     *
     * @param port {@code 0} picks a free port, see {@link #port()}
     */
    public static ManagementServer start(
            String host, int port, Supplier<Health> health, Supplier<Health> ready, Supplier<String> state) {
        return start(host, port, health, ready, state, null);
    }

    /** As above, plus {@code /metrics} in the Prometheus text format when {@code metrics} is not {@code null}. */
    public static ManagementServer start(
            String host,
            int port,
            Supplier<Health> health,
            Supplier<Health> ready,
            Supplier<String> state,
            Supplier<String> metrics) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(host, port), 16);
            ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "management-http");
                t.setDaemon(true);
                return t;
            });
            server.setExecutor(executor);
            server.createContext("/health", exchange -> healthResponse(exchange, health));
            server.createContext("/ready", exchange -> healthResponse(exchange, ready));
            server.createContext("/state", exchange -> respond(exchange, 200, state.get()));
            if (metrics != null) {
                server.createContext(
                        "/metrics", exchange -> respond(exchange, 200, metrics.get(), PrometheusWriter.CONTENT_TYPE));
            }
            server.start();
            return new ManagementServer(server, executor);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot start management server on " + host + ":" + port, e);
        }
    }

    /** Starts the server from {@code management.http.*} keys, or returns {@code null} if disabled. */
    public static ManagementServer start(
            Config config, int defaultPort, Supplier<Health> health, Supplier<Health> ready, Supplier<String> state) {
        return start(config, defaultPort, health, ready, state, null);
    }

    public static ManagementServer start(
            Config config,
            int defaultPort,
            Supplier<Health> health,
            Supplier<Health> ready,
            Supplier<String> state,
            Supplier<String> metrics) {
        if (!config.bool("management.http.enabled", true)) {
            return null;
        }
        return start(
                config.string("management.http.host", "127.0.0.1"),
                config.integer("management.http.port", defaultPort),
                health,
                ready,
                state,
                metrics);
    }

    public int port() {
        return server.getAddress().getPort();
    }

    private static void healthResponse(HttpExchange exchange, Supplier<Health> check) throws IOException {
        Health health;
        try {
            health = check.get();
        } catch (RuntimeException e) {
            health = Health.down("check failed: " + e.getMessage());
        }
        String body = new JsonWriter()
                .field("status", health.up() ? "UP" : "DOWN")
                .field("detail", health.detail())
                .finish();
        respond(exchange, health.up() ? 200 : 503, body);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        respond(exchange, status, body, "application/json");
    }

    private static void respond(HttpExchange exchange, int status, String body, String contentType) throws IOException {
        try (exchange) {
            if (!"GET".equals(exchange.getRequestMethod()) && !"HEAD".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", contentType);
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
