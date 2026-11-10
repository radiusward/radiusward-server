/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.ItemParser;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The gateway's CoA API on its management port (ADR 0036), only with {@code coa.api.token}:
 *
 * <pre>
 * POST /coa/disconnect?user=alice                       every active session of the user
 * POST /coa/disconnect?nas=core&amp;session=0000ABCD        one session (NAS entries without device identity)
 * POST /coa/update?user=alice      body: attribute list  CoA-Request, e.g. Session-Timeout = 600, Filter-Id = "x"
 * Authorization: Bearer &lt;coa.api.token&gt;
 * </pre>
 *
 * Answers JSON: one result per session ({@code ack}, {@code nak} with the Error-Cause, {@code timeout},
 * {@code unreachable}). Requests are handled on a thread of their own, so a slow NAS never holds up {@code /health}.
 */
final class CoaApi implements HttpHandler {

    private static final Logger LOG = LogManager.getLogger(CoaApi.class);

    private final CoaService service;
    private final byte[] token;
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "coa-api");
        t.setDaemon(true);
        return t;
    });

    CoaApi(CoaService service, String token) {
        this.service = service;
        this.token = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
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
        byte[] body = exchange.getRequestBody().readAllBytes();
        executor.execute(() -> {
            try {
                answer(exchange, new String(body, StandardCharsets.UTF_8));
            } catch (IOException e) {
                LOG.debug("CoA API answer failed: {}", e.toString());
            }
        });
    }

    private void answer(HttpExchange exchange, String body) throws IOException {
        String path = exchange.getRequestURI().getPath();
        Map<String, String> q = query(exchange.getRequestURI().getRawQuery());
        try {
            List<AttributeItem> attributes = body.isBlank() ? List.of() : ItemParser.parse(body, "request body");
            boolean update = path.endsWith("/update");
            if (update == attributes.isEmpty()) {
                respond(
                        exchange,
                        400,
                        error(update ? "/coa/update needs attributes in the body" : "/coa/disconnect takes no body"));
                return;
            }
            List<CoaService.SessionResult> results;
            if (q.containsKey("user")) {
                results =
                        update ? service.changeUser(q.get("user"), attributes) : service.disconnectUser(q.get("user"));
            } else if (q.containsKey("nas") && q.containsKey("session")) {
                results = service.toSession(q.get("nas"), q.get("session"), attributes);
            } else {
                respond(exchange, 400, error("user=<name>, or nas=<entry>&session=<Acct-Session-Id>"));
                return;
            }
            LOG.info("CoA API {} {}: {} session(s)", path, q, results.size());
            respond(exchange, 200, json(results));
        } catch (IllegalArgumentException e) {
            respond(exchange, 400, error(e.getMessage()));
        } catch (TimeoutException e) {
            respond(exchange, 503, error("the cluster did not answer: " + e.getMessage()));
        } catch (RuntimeException e) {
            LOG.warn("CoA API {} failed", path, e);
            respond(exchange, 500, error(e.toString()));
        }
    }

    static String json(List<CoaService.SessionResult> results) {
        StringBuilder b = new StringBuilder("{\"sessions\":[");
        for (int i = 0; i < results.size(); i++) {
            CoaService.SessionResult r = results.get(i);
            b.append(i == 0 ? "" : ",")
                    .append("{\"nas\":")
                    .append(quote(r.nas()))
                    .append(",\"session\":")
                    .append(quote(r.acctSessionId()))
                    .append(",\"user\":")
                    .append(quote(r.user()))
                    .append(",\"result\":")
                    .append(quote(r.outcome().name().toLowerCase(java.util.Locale.ROOT)));
            if (r.errorCause() != 0) {
                b.append(",\"errorCause\":").append(r.errorCause());
            }
            b.append('}');
        }
        return b.append("]}").toString();
    }

    private static String error(String message) {
        return "{\"error\":" + quote(message) + "}";
    }

    static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> q = new HashMap<>();
        if (raw == null) {
            return q;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                q.put(
                        URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return q;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    void close() {
        executor.shutdownNow();
    }
}
