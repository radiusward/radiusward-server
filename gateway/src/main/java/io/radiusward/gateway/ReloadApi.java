/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.radiusward.common.config.ConfigException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.function.Supplier;

/**
 * {@code POST /reload} on the management port (ADR 0054), with {@code Authorization: Bearer <reload.api.token>}: reads
 * the configuration files again and applies what can change at run time. 200 with what was applied, 400 with the
 * reason when the configuration does not load (nothing changes then).
 */
final class ReloadApi implements HttpHandler {

    private final byte[] token;
    private final Supplier<String> reload;

    /**
     * @param reload reloads and returns a summary; throws {@link ConfigException} for a configuration that does not load
     */
    ReloadApi(String token, Supplier<String> reload) {
        if (token.length() < 16) {
            throw new ConfigException("reload.api.token: at least 16 characters");
        }
        this.token = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
        this.reload = reload;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        if (auth == null || !MessageDigest.isEqual(auth.getBytes(StandardCharsets.UTF_8), token)) {
            respond(exchange, 401, "{\"error\":\"missing or wrong bearer token\"}");
            return;
        }
        if (!exchange.getRequestMethod().equals("POST")) {
            respond(exchange, 405, "{\"error\":\"POST expected\"}");
            return;
        }
        try {
            respond(exchange, 200, "{\"reloaded\":" + CoaApi.quote(reload.get()) + "}");
        } catch (ConfigException e) {
            respond(exchange, 400, "{\"error\":" + CoaApi.quote(e.getMessage()) + "}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
