/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class ManagementServerTest {

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> get(int port, String path) throws Exception {
        return http.send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void endpoints() throws Exception {
        AtomicBoolean ready = new AtomicBoolean(false);
        try (ManagementServer server = ManagementServer.start(
                "127.0.0.1",
                0,
                () -> Health.up("agents running"),
                () -> ready.get() ? Health.up("leader known") : Health.down("no leader"),
                () -> new JsonWriter()
                        .field("role", "LEADER")
                        .field("applied", 5)
                        .finish(),
                () -> new PrometheusWriter()
                        .counter("radiusward_x_total", "x")
                        .sample(5)
                        .finish())) {
            HttpResponse<String> health = get(server.port(), "/health");
            assertThat(health.statusCode()).isEqualTo(200);
            assertThat(health.body()).isEqualTo("{\"status\":\"UP\",\"detail\":\"agents running\"}");
            assertThat(health.headers().firstValue("Content-Type")).contains("application/json");

            assertThat(get(server.port(), "/ready").statusCode()).isEqualTo(503);
            ready.set(true);
            assertThat(get(server.port(), "/ready").statusCode()).isEqualTo(200);

            HttpResponse<String> state = get(server.port(), "/state");
            assertThat(state.body()).isEqualTo("{\"role\":\"LEADER\",\"applied\":5}");

            HttpResponse<String> metrics = get(server.port(), "/metrics");
            assertThat(metrics.statusCode()).isEqualTo(200);
            assertThat(metrics.headers().firstValue("Content-Type")).contains(PrometheusWriter.CONTENT_TYPE);
            assertThat(metrics.body()).endsWith("radiusward_x_total 5\n");

            HttpResponse<String> post = http.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/state"))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(post.statusCode()).isEqualTo(405);
        }
    }

    @Test
    void failingCheckIsReportedAsDown() throws Exception {
        try (ManagementServer server = ManagementServer.start(
                "127.0.0.1",
                0,
                () -> {
                    throw new IllegalStateException("boom");
                },
                () -> Health.up(""),
                () -> "{}")) {
            HttpResponse<String> health = get(server.port(), "/health");
            assertThat(health.statusCode()).isEqualTo(503);
            assertThat(health.body()).contains("check failed: boom");
        }
    }

    @Test
    void configuredOrDisabled() throws Exception {
        assertThat(ManagementServer.start(
                        Config.of(Map.of("management.http.enabled", "false")), 0, () -> null, () -> null, () -> ""))
                .isNull();
        try (ManagementServer server = ManagementServer.start(
                Config.of(Map.of("management.http.port", "0")),
                9999,
                () -> Health.up(""),
                () -> Health.up(""),
                () -> "{}")) {
            assertThat(get(server.port(), "/health").statusCode()).isEqualTo(200);
        }
    }

    @Test
    void jsonEscapingAndNesting() {
        String json = new JsonWriter()
                .field("s", "a\"b\\c\nd\te\u0001")
                .field("b", true)
                .field("n", (String) null)
                .object("log")
                .field("dropped", 0)
                .end()
                .field("after", 1)
                .finish();
        assertThat(json)
                .isEqualTo(
                        "{\"s\":\"a\\\"b\\\\c\\nd\\te\\u0001\",\"b\":true,\"n\":null,\"log\":{\"dropped\":0},\"after\":1}");
    }
}
