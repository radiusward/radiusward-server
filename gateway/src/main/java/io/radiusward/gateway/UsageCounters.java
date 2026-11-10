/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.DayOfWeek;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/**
 * Usage counters (ADR 0049), like other servers' SQL counters: each counter names a check item holding a user's
 * limit (e.g. {@code Max-Daily-Session := 3600}), a period that resets it, and what it counts — session time or
 * octets — from the accounting the PostgreSQL sink exports ({@code accounting_session}), or from a query of one's
 * own. A user over the limit is rejected; for time, the Accept's Session-Timeout is cut to what is left before the
 * limit or the period's end.
 */
final class UsageCounters {

    enum Kind {
        TIME,
        OCTETS
    }

    enum Reset {
        DAILY,
        WEEKLY,
        MONTHLY,
        NEVER
    }

    /**
     * @param check the check item that holds a user's limit
     * @param reply for octets, an attribute that gets the octets left (e.g. a vendor's data limit); {@code null}: none
     */
    record Counter(String name, String check, Kind kind, Reset reset, String query, String reply) {}

    /** How much a user used since the period began. */
    @FunctionalInterface
    interface Source {
        long usage(Counter counter, String user, Instant periodStart) throws Exception;
    }

    /** Session time since {@code ?2}: the part of each session after it. Parameters: user, period start. */
    static final String TIME_QUERY = "SELECT COALESCE(SUM(GREATEST(COALESCE(s.session_seconds, 0)"
            + " - GREATEST(CAST(EXTRACT(EPOCH FROM (p.since - s.started_at)) AS bigint), 0), 0)), 0)"
            + " FROM accounting_session s, (SELECT CAST(? AS text) AS name, CAST(? AS timestamptz) AS since) p"
            + " WHERE s.user_name = p.name"
            + " AND s.started_at + COALESCE(s.session_seconds, 0) * interval '1 second' > p.since";

    /** Octets of the sessions seen since the period began (whole sessions). Parameters: user, period start. */
    static final String OCTETS_QUERY = "SELECT COALESCE(SUM(s.input_octets + s.output_octets), 0)"
            + " FROM accounting_session s WHERE s.user_name = ? AND s.last_received_at >= ?";

    /** When a user first logged in; {@code null} if never (ADR 0060). */
    @FunctionalInterface
    interface FirstLogin {
        Instant first(String user) throws Exception;
    }

    /** The start of the user's first exported session. Parameter: user. */
    static final String FIRST_QUERY = "SELECT MIN(started_at) FROM accounting_session WHERE user_name = ?";

    private final List<Counter> counters;
    private final Source source;
    private final ZoneId zone;
    private final FirstLogin firstLogin;

    UsageCounters(List<Counter> counters, Source source, ZoneId zone) {
        this(counters, source, zone, user -> null);
    }

    UsageCounters(List<Counter> counters, Source source, ZoneId zone, FirstLogin firstLogin) {
        this.counters = List.copyOf(counters);
        this.source = source;
        this.zone = zone;
        this.firstLogin = firstLogin;
    }

    Instant firstLogin(String user) throws Exception {
        return firstLogin.first(user);
    }

    List<Counter> counters() {
        return counters;
    }

    ZoneId zone() {
        return zone;
    }

    long usage(Counter counter, String user, Instant periodStart) throws Exception {
        return source.usage(counter, user, periodStart);
    }

    /** {@code auth.counters} and {@code auth.counter.*}; {@code null} without counters and connection. */
    static UsageCounters from(Config config) {
        List<String> names = config.list("auth.counters", List.of());
        if (names.isEmpty() && !config.has("auth.counter.sql.url")) {
            return null; // without counters, the connection alone serves Expire-After
        }
        List<Counter> counters = new ArrayList<>();
        for (String raw : names) {
            String name = raw.trim();
            String prefix = "auth.counter." + name + ".";
            Kind kind = choice(Kind.class, prefix + "kind", config.string(prefix + "kind", "time"));
            Reset reset = choice(Reset.class, prefix + "reset", config.string(prefix + "reset", "daily"));
            String query = config.string(prefix + "query", kind == Kind.TIME ? TIME_QUERY : OCTETS_QUERY);
            String reply = config.string(prefix + "reply", "").trim();
            counters.add(new Counter(
                    name, config.string(prefix + "check").trim(), kind, reset, query, reply.isEmpty() ? null : reply));
        }
        Properties properties = new Properties();
        properties.setProperty("user", config.string("auth.counter.sql.user", ""));
        properties.setProperty("password", config.string("auth.counter.sql.password", ""));
        String url = config.string("auth.counter.sql.url");
        return new UsageCounters(
                counters,
                sql(url, properties),
                zone(config),
                first(url, properties, config.string("auth.counter.first.query", FIRST_QUERY)));
    }

    static FirstLogin first(String url, Properties properties, String query) {
        return user -> {
            try (Connection c = DriverManager.getConnection(url, properties);
                    PreparedStatement s = c.prepareStatement(query)) {
                s.setQueryTimeout(5);
                s.setString(1, user);
                try (ResultSet r = s.executeQuery()) {
                    Timestamp t = r.next() ? r.getTimestamp(1) : null;
                    return t == null ? null : t.toInstant();
                }
            }
        };
    }

    /** {@code auth.time.zone}: the zone of Login-Time windows and counter periods; the system's by default. */
    static ZoneId zone(Config config) {
        String zone = config.string("auth.time.zone", "").trim();
        try {
            return zone.isEmpty() ? ZoneId.systemDefault() : ZoneId.of(zone);
        } catch (java.time.DateTimeException e) {
            throw new ConfigException("auth.time.zone: unknown zone " + zone, e);
        }
    }

    private static <E extends Enum<E>> E choice(Class<E> type, String key, String value) {
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ConfigException(key + ": unknown value " + value, e);
        }
    }

    static Source sql(String url, Properties properties) {
        return (counter, user, since) -> {
            try (Connection c = DriverManager.getConnection(url, properties);
                    PreparedStatement s = c.prepareStatement(counter.query())) {
                s.setQueryTimeout(5);
                s.setString(1, user);
                s.setTimestamp(2, Timestamp.from(since));
                try (ResultSet r = s.executeQuery()) {
                    return r.next() ? r.getLong(1) : 0;
                }
            }
        };
    }

    /** When the period that contains {@code now} began. */
    static Instant periodStart(Reset reset, ZonedDateTime now) {
        ZonedDateTime day = now.truncatedTo(ChronoUnit.DAYS);
        return switch (reset) {
            case DAILY -> day.toInstant();
            case WEEKLY ->
                day.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)).toInstant();
            case MONTHLY -> day.withDayOfMonth(1).toInstant();
            case NEVER -> Instant.EPOCH;
        };
    }

    /** When the period that contains {@code now} ends; {@code null} for {@code never}. */
    static Instant periodEnd(Reset reset, ZonedDateTime now) {
        ZonedDateTime day = now.truncatedTo(ChronoUnit.DAYS);
        return switch (reset) {
            case DAILY -> day.plusDays(1).toInstant();
            case WEEKLY -> day.with(TemporalAdjusters.next(DayOfWeek.MONDAY)).toInstant();
            case MONTHLY -> day.withDayOfMonth(1).plusMonths(1).toInstant();
            case NEVER -> null;
        };
    }
}
