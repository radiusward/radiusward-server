/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.LongSupplier;
import org.agrona.DirectBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Per-request debug traces (ADR 0052): Access-Requests that match a condition — a user, a NAS entry or a
 * Calling-Station-Id — are logged with their attributes, the decisions taken (store, groups, checks, limits, pools,
 * rules) and the reply, to the logger {@code io.radiusward.trace}. Conditions come from {@code trace.users},
 * {@code trace.nas} and {@code trace.stations}, or for a while from the management API ({@code trace.api.token}).
 * Secrets (passwords, MS-CHAP and EAP payloads, keys, the Message-Authenticator) are never written. Without conditions
 * a request costs one volatile read.
 */
final class Tracer {

    static final Logger TRACE = LogManager.getLogger("io.radiusward.trace");

    /** The longest a condition from the API lasts. */
    static final Duration MAX_FOR = Duration.ofHours(24);

    private static final int USER_NAME = 1;
    private static final int CALLING_STATION_ID = 31;

    enum Kind {
        USER,
        NAS,
        STATION
    }

    /** {@code until} in clock milliseconds; {@code Long.MAX_VALUE} for configured ones. */
    record Condition(Kind kind, String value, long until) {}

    /** The steps of one traced request. */
    static final class Trace {
        final StringBuilder steps = new StringBuilder();
        final long started = System.nanoTime();
        boolean reason;

        void note(String step) {
            steps.append("\n  ").append(step);
        }

        /** A step that explains a reject or a missing answer. */
        void because(String step) {
            note(step);
            reason = true;
        }
    }

    private final Dictionary dictionary;
    private final VendorFormats formats;
    private final LongSupplier clockMillis;
    private final List<Condition> configured;
    private volatile List<Condition> conditions;

    Tracer(Dictionary dictionary, List<Condition> configured, LongSupplier clockMillis) {
        this.dictionary = dictionary;
        this.formats = VendorFormats.from(dictionary);
        this.clockMillis = clockMillis;
        this.configured = List.copyOf(configured);
        this.conditions = this.configured;
    }

    /** {@code trace.users}, {@code trace.nas}, {@code trace.stations}. */
    static Tracer from(Config config, Dictionary dictionary) {
        List<Condition> configured = new ArrayList<>();
        for (String user : config.list("trace.users", List.of())) {
            configured.add(new Condition(Kind.USER, user.trim(), Long.MAX_VALUE));
        }
        for (String nas : config.list("trace.nas", List.of())) {
            configured.add(new Condition(Kind.NAS, nas.trim(), Long.MAX_VALUE));
        }
        for (String station : config.list("trace.stations", List.of())) {
            configured.add(new Condition(Kind.STATION, normalized(station), Long.MAX_VALUE));
        }
        return new Tracer(dictionary, configured, System::currentTimeMillis);
    }

    /** A trace for this request if a condition matches, else {@code null}. */
    Trace start(RadiusPacket request, NasClient nas) {
        List<Condition> current = conditions;
        if (current.isEmpty()) {
            return null;
        }
        long now = clockMillis.getAsLong();
        String user = null;
        String station = null;
        for (Condition c : current) {
            if (c.until() <= now) {
                continue;
            }
            boolean match = switch (c.kind()) {
                case NAS -> c.value().equals(nas.name());
                case USER -> {
                    if (user == null) {
                        user = text(request, USER_NAME);
                    }
                    yield c.value().equals(user);
                }
                case STATION -> {
                    if (station == null) {
                        String s = text(request, CALLING_STATION_ID);
                        station = s == null ? "" : normalized(s);
                    }
                    yield c.value().equals(station);
                }
            };
            if (match) {
                Trace trace = new Trace();
                trace.note("request: "
                        + attributes(
                                request.buffer(),
                                request.offset() + RadiusPacket.HEADER_LENGTH,
                                request.offset() + request.length()));
                return trace;
            }
        }
        return null;
    }

    /** Logs the trace with the decision and the reply attributes ({@code replyLength} bytes after the header). */
    void finish(Trace trace, RadiusPacket request, NasClient nas, int code, DirectBuffer reply, int replyLength) {
        TRACE.info("{}", render(trace, request, nas, code, reply, replyLength));
    }

    String render(Trace trace, RadiusPacket request, NasClient nas, int code, DirectBuffer reply, int replyLength) {
        if (code != AccessHandler.ACCEPT && code != AccessHandler.CHALLENGE && !trace.reason) {
            trace.note(code == AccessHandler.DROP ? "no answer" : "credentials or method rejected");
        }
        if (code != AccessHandler.DROP && replyLength > 0) {
            trace.note("reply: "
                    + attributes(reply, RadiusPacket.HEADER_LENGTH, RadiusPacket.HEADER_LENGTH + replyLength));
        }
        long micros = (System.nanoTime() - trace.started) / 1000;
        return "trace: Access-Request id " + request.identifier() + " from NAS " + nas.name() + " -> "
                + (code == AccessHandler.DROP ? "no answer" : RadiusCode.name(code)) + " in " + micros + " µs"
                + trace.steps;
    }

    private String text(RadiusPacket request, int type) {
        int at = request.findAttribute(type);
        if (at < 0) {
            return null;
        }
        return request.buffer()
                .getStringWithoutLengthUtf8(at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
    }

    private static String normalized(String station) {
        return station.trim().toLowerCase(Locale.ROOT).replaceAll("[^0-9a-z]", "");
    }

    /** The attributes between two offsets, by name, secrets hidden. */
    String attributes(DirectBuffer buffer, int start, int end) {
        StringBuilder out = new StringBuilder();
        AttributeCursor cursor = new AttributeCursor(formats).wrap(buffer, start, end);
        while (cursor.next()) {
            AttributeDef def = cursor.vendorId() == 0
                    ? dictionary.attribute(cursor.type())
                    : dictionary.vendorAttribute(cursor.vendorId(), cursor.type());
            String name = def == null
                    ? (cursor.vendorId() == 0
                            ? "Attr-" + cursor.type()
                            : "Vendor-" + cursor.vendorId() + "-Attr-" + cursor.type())
                    : def.name();
            if (!out.isEmpty()) {
                out.append(", ");
            }
            out.append(name).append(" = ");
            if (secret(def, name)) {
                out.append("<").append(cursor.valueLength()).append(" bytes>");
            } else if (def == null) {
                out.append("0x")
                        .append(io.radiusward.radius.codec.AttributeValues.hex(
                                cursor.buffer(), cursor.valueOffset(), cursor.valueLength()));
            } else {
                out.append(AttributeText.decode(def, cursor.buffer(), cursor.valueOffset(), cursor.valueLength()));
            }
        }
        return out.toString();
    }

    static boolean secret(AttributeDef def, String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return (def != null && def.encrypt() != null)
                || n.contains("password")
                || n.startsWith("ms-chap")
                || n.startsWith("ms-mppe")
                || n.equals("eap-message")
                || n.equals("message-authenticator")
                || n.contains("key");
    }

    // ---- conditions from the API --------------------------------------------------------------------------------

    List<Condition> conditions() {
        long now = clockMillis.getAsLong();
        return conditions.stream().filter(c -> c.until() > now).toList();
    }

    synchronized void add(Kind kind, String value, Duration duration) {
        long now = clockMillis.getAsLong();
        List<Condition> next = new ArrayList<>(conditions());
        next.add(new Condition(
                kind, kind == Kind.STATION ? normalized(value) : value.trim(), now + duration.toMillis()));
        conditions = List.copyOf(next);
        TRACE.info("trace: {} {} for {}", kind.name().toLowerCase(Locale.ROOT), value, duration);
    }

    /** Drops the conditions from the API; the configured ones stay. */
    synchronized void clear() {
        conditions = configured;
        TRACE.info("trace: conditions from the API removed");
    }

    /**
     * {@code POST /trace?user=|nas=|station=<value>&for=<duration>} adds a condition (default 15 minutes, at most a
     * day), {@code GET /trace} lists them, {@code DELETE /trace} removes those from the API. Bearer token.
     */
    HttpHandler api(String token) {
        if (token.length() < 16) {
            throw new ConfigException("trace.api.token: at least 16 characters");
        }
        byte[] expected = ("Bearer " + token).getBytes(StandardCharsets.UTF_8);
        return exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !MessageDigest.isEqual(auth.getBytes(StandardCharsets.UTF_8), expected)) {
                respond(exchange, 401, "{\"error\":\"missing or wrong bearer token\"}");
                return;
            }
            switch (exchange.getRequestMethod()) {
                case "GET" -> respond(exchange, 200, json(conditions()));
                case "DELETE" -> {
                    clear();
                    respond(exchange, 200, json(conditions()));
                }
                case "POST" -> {
                    Map<String, String> q = query(exchange.getRequestURI().getRawQuery());
                    Duration duration;
                    try {
                        duration = q.containsKey("for")
                                ? Config.of(Map.of("for", q.get("for"))).duration("for")
                                : Duration.ofMinutes(15);
                    } catch (RuntimeException e) {
                        respond(exchange, 400, "{\"error\":\"for: a duration such as 10m\"}");
                        return;
                    }
                    if (duration.isNegative() || duration.isZero() || duration.compareTo(MAX_FOR) > 0) {
                        respond(exchange, 400, "{\"error\":\"for: up to 24h\"}");
                        return;
                    }
                    Kind kind = q.containsKey("user")
                            ? Kind.USER
                            : q.containsKey("nas") ? Kind.NAS : q.containsKey("station") ? Kind.STATION : null;
                    if (kind == null) {
                        respond(exchange, 400, "{\"error\":\"user=, nas= or station=\"}");
                        return;
                    }
                    add(kind, q.get(kind.name().toLowerCase(Locale.ROOT)), duration);
                    respond(exchange, 200, json(conditions()));
                }
                default -> respond(exchange, 405, "{\"error\":\"GET, POST or DELETE\"}");
            }
        };
    }

    private String json(List<Condition> list) {
        StringBuilder b = new StringBuilder("{\"conditions\":[");
        for (int i = 0; i < list.size(); i++) {
            Condition c = list.get(i);
            b.append(i == 0 ? "" : ",")
                    .append("{\"")
                    .append(c.kind().name().toLowerCase(Locale.ROOT))
                    .append("\":")
                    .append(CoaApi.quote(c.value()))
                    .append(",\"until\":")
                    .append(CoaApi.quote(
                            c.until() == Long.MAX_VALUE
                                    ? "configured"
                                    : Instant.ofEpochMilli(c.until()).toString()))
                    .append('}');
        }
        return b.append("]}").toString();
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> q = new LinkedHashMap<>();
        if (raw != null) {
            for (String pair : raw.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    q.put(
                            URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
                }
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
}
