/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.ItemParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The RADIUS server's CoA API on its management port (ADR 0036), only with {@code coa.api.token}:
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
            HttpJson.respond(exchange, 401, "{\"error\":\"missing or wrong bearer token\"}");
            return;
        }
        if (!exchange.getRequestMethod().equals("POST")) {
            HttpJson.respond(exchange, 405, "{\"error\":\"POST expected\"}");
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
        Map<String, String> q = HttpJson.query(exchange.getRequestURI().getRawQuery());
        try {
            List<AttributeItem> attributes = body.isBlank() ? List.of() : ItemParser.parse(body, "request body");
            boolean update = path.endsWith("/update");
            if (update == attributes.isEmpty()) {
                HttpJson.respond(
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
                HttpJson.respond(exchange, 400, error("user=<name>, or nas=<entry>&session=<Acct-Session-Id>"));
                return;
            }
            LOG.info("CoA API {} {}: {} session(s)", path, q, results.size());
            HttpJson.respond(exchange, 200, json(results));
        } catch (IllegalArgumentException e) {
            HttpJson.respond(exchange, 400, error(e.getMessage()));
        } catch (TimeoutException e) {
            HttpJson.respond(exchange, 503, error("the cluster did not answer: " + e.getMessage()));
        } catch (RuntimeException e) {
            LOG.warn("CoA API {} failed", path, e);
            HttpJson.respond(exchange, 500, error(e.toString()));
        }
    }

    static String json(List<CoaService.SessionResult> results) {
        StringBuilder b = new StringBuilder("{\"sessions\":[");
        for (int i = 0; i < results.size(); i++) {
            CoaService.SessionResult r = results.get(i);
            b.append(i == 0 ? "" : ",")
                    .append("{\"nas\":")
                    .append(HttpJson.quote(r.nas()))
                    .append(",\"session\":")
                    .append(HttpJson.quote(r.acctSessionId()))
                    .append(",\"user\":")
                    .append(HttpJson.quote(r.user()))
                    .append(",\"result\":")
                    .append(HttpJson.quote(r.outcome().name().toLowerCase(java.util.Locale.ROOT)));
            if (r.errorCause() != 0) {
                b.append(",\"errorCause\":").append(r.errorCause());
            }
            b.append('}');
        }
        return b.append("]}").toString();
    }

    private static String error(String message) {
        return "{\"error\":" + HttpJson.quote(message) + "}";
    }

    void close() {
        executor.shutdownNow();
    }
}
