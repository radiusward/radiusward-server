/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static io.radiusward.radius.codec.attributes.Ietf.CALLING_STATION_ID;
import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;

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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
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
    private volatile List<Condition> configured;
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
        return new Tracer(dictionary, configured(config), System::currentTimeMillis);
    }

    /** Takes the configured conditions of a reloaded configuration (ADR 0054); those from the API stay. */
    synchronized void reconfigure(Config config) {
        List<Condition> next = configured(config);
        List<Condition> fromApi =
                conditions().stream().filter(c -> c.until() != Long.MAX_VALUE).toList();
        configured = List.copyOf(next);
        List<Condition> all = new ArrayList<>(next);
        all.addAll(fromApi);
        conditions = List.copyOf(all);
    }

    private static List<Condition> configured(Config config) {
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
        return configured;
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
                        user = request.string(USER_NAME);
                    }
                    yield c.value().equals(user);
                }
                case STATION -> {
                    if (station == null) {
                        String s = request.string(CALLING_STATION_ID);
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

    private static String normalized(String station) {
        return station.trim().toLowerCase(Locale.ROOT).replaceAll("[^0-9a-z]", "");
    }

    /** The attributes between two offsets, by name, secrets hidden. */
    String attributes(DirectBuffer buffer, int start, int end) {
        StringBuilder out = new StringBuilder();
        AttributeCursor cursor = new AttributeCursor(formats).wrap(buffer, start, end);
        while (cursor.next()) {
            AttributeDef def = AttributeText.definition(dictionary, cursor);
            String name = AttributeText.name(def, cursor);
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

    /**
     * Whether a value stays out of traces, judged by the dictionary name without a vendor's prefix: passwords, keys,
     * everything of CHAP, MS-CHAP and MPPE (the dictionaries name Microsoft's {@code CHAP-Challenge} and {@code
     * CHAP2-Response}: with the challenge, a response is enough to guess the password offline), EAP and
     * Message-Authenticator.
     */
    static boolean secret(AttributeDef def, String name) {
        String n = (def != null ? def.name() : name).toLowerCase(Locale.ROOT);
        return (def != null && def.encrypt() != null)
                || n.contains("password")
                || n.contains("chap")
                || n.contains("mppe")
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
                HttpJson.respond(exchange, 401, "{\"error\":\"missing or wrong bearer token\"}");
                return;
            }
            switch (exchange.getRequestMethod()) {
                case "GET" -> HttpJson.respond(exchange, 200, json(conditions()));
                case "DELETE" -> {
                    clear();
                    HttpJson.respond(exchange, 200, json(conditions()));
                }
                case "POST" -> {
                    Map<String, String> q =
                            HttpJson.query(exchange.getRequestURI().getRawQuery());
                    Duration duration;
                    try {
                        duration = q.containsKey("for")
                                ? Config.of(Map.of("for", q.get("for"))).duration("for")
                                : Duration.ofMinutes(15);
                    } catch (RuntimeException e) {
                        HttpJson.respond(exchange, 400, "{\"error\":\"for: a duration such as 10m\"}");
                        return;
                    }
                    if (duration.isNegative() || duration.isZero() || duration.compareTo(MAX_FOR) > 0) {
                        HttpJson.respond(exchange, 400, "{\"error\":\"for: up to 24h\"}");
                        return;
                    }
                    Kind kind = q.containsKey("user")
                            ? Kind.USER
                            : q.containsKey("nas") ? Kind.NAS : q.containsKey("station") ? Kind.STATION : null;
                    if (kind == null) {
                        HttpJson.respond(exchange, 400, "{\"error\":\"user=, nas= or station=\"}");
                        return;
                    }
                    add(kind, q.get(kind.name().toLowerCase(Locale.ROOT)), duration);
                    HttpJson.respond(exchange, 200, json(conditions()));
                }
                default -> HttpJson.respond(exchange, 405, "{\"error\":\"GET, POST or DELETE\"}");
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
                    .append(HttpJson.quote(c.value()))
                    .append(",\"until\":")
                    .append(HttpJson.quote(
                            c.until() == Long.MAX_VALUE
                                    ? "configured"
                                    : Instant.ofEpochMilli(c.until()).toString()))
                    .append('}');
        }
        return b.append("]}").toString();
    }
}
