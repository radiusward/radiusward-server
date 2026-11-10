/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * The default counter queries (ADR 0049) against PostgreSQL with the sink's {@code accounting_session} columns: time
 * counts only the part of a session after the period began, octets count the sessions seen in the period. Skipped
 * where Docker is missing, a failure where it is required.
 */
class UsageCountersIT {

    private PostgreSQLContainer postgres;

    @AfterEach
    void stop() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    @Test
    void defaultQueriesOverTheExportedSessions() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        long deadline = System.nanoTime() + 30_000_000_000L; // the mapped port may lag behind (Colima)
        while (true) {
            try (Connection probe = DriverManager.getConnection(
                    postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())) {
                if (probe.isValid(5)) {
                    break;
                }
            } catch (java.sql.SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("PostgreSQL not reachable", e);
                }
                Thread.sleep(250);
            }
        }
        try (Connection c = DriverManager.getConnection(
                        postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
                Statement s = c.createStatement()) {
            s.execute("CREATE TABLE accounting_session (user_name text, session_seconds bigint,"
                    + " input_octets bigint NOT NULL, output_octets bigint NOT NULL, started_at timestamptz,"
                    + " last_received_at timestamptz NOT NULL)");
            s.execute("INSERT INTO accounting_session VALUES"
                    // yesterday 23:00 for 2 h: one hour today
                    + " ('alice', 7200, 100, 200, '2027-01-14 23:00:00+00', '2027-01-15 01:00:00+00'),"
                    // today, 30 min
                    + " ('alice', 1800, 1000, 2000, '2027-01-15 05:00:00+00', '2027-01-15 05:30:00+00'),"
                    // last week: nothing today
                    + " ('alice', 600, 5, 5, '2027-01-08 10:00:00+00', '2027-01-08 10:10:00+00'),"
                    // started, no time reported yet
                    + " ('alice', NULL, 0, 0, '2027-01-15 07:59:00+00', '2027-01-15 07:59:00+00'),"
                    + " ('bob', 50, 1, 1, '2027-01-15 06:00:00+00', '2027-01-15 06:01:00+00')");
        }
        UsageCounters counters = UsageCounters.from(Config.of(Map.of(
                "auth.counters", "daily, data",
                "auth.counter.daily.check", "Max-Daily-Session",
                "auth.counter.data.check", "Max-Monthly-Octets",
                "auth.counter.data.kind", "octets",
                "auth.counter.data.reset", "monthly",
                "auth.counter.sql.url", postgres.getJdbcUrl(),
                "auth.counter.sql.user", postgres.getUsername(),
                "auth.counter.sql.password", postgres.getPassword(),
                "auth.time.zone", "UTC")));
        UsageCounters.Counter daily = counters.counters().get(0);
        UsageCounters.Counter data = counters.counters().get(1);
        Instant today = Instant.parse("2027-01-15T00:00:00Z");
        assertThat(counters.usage(daily, "alice", today)).isEqualTo(3600 + 1800);
        assertThat(counters.usage(daily, "bob", today)).isEqualTo(50);
        assertThat(counters.usage(daily, "nobody", today)).isZero();
        assertThat(counters.usage(data, "alice", Instant.parse("2027-01-01T00:00:00Z")))
                .isEqualTo(100 + 200 + 1000 + 2000 + 10);
        assertThat(counters.usage(data, "alice", today)).isEqualTo(100 + 200 + 1000 + 2000);
    }
}
