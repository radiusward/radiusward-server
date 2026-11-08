/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.postgres;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.export.Attributes;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.FencedException;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.export.SinkContext;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Against a real PostgreSQL 17 (Testcontainers). Skipped without Docker, unless
 * {@code -Dradiusward.require.docker=true} (CI), where a missing Docker fails the build.
 */
class PostgresSinkTest {

    private static final Attributes ATTRIBUTES = new Attributes(DictionaryLoader.loadBundled());
    private static final AtomicInteger SCHEMAS = new AtomicInteger();
    private static PostgreSQLContainer postgres;

    private String schema;

    @BeforeAll
    static void startPostgres() {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        // Docker on macOS (Colima) forwards the published port a moment after the container is ready
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (true) {
            try (Connection c = DriverManager.getConnection(
                    postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())) {
                if (c.isValid(5)) {
                    return;
                }
            } catch (SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("PostgreSQL not reachable", e);
                }
                try {
                    Thread.sleep(250);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    @AfterAll
    static void stopPostgres() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    @BeforeEach
    void freshSchema() throws SQLException {
        schema = "t" + SCHEMAS.incrementAndGet();
        try (Connection c = connect(null);
                Statement st = c.createStatement()) {
            st.execute("CREATE SCHEMA " + schema);
        }
    }

    private Connection connect(String inSchema) throws SQLException {
        String url = postgres.getJdbcUrl() + (inSchema == null ? "" : "&currentSchema=" + inSchema);
        return DriverManager.getConnection(
                url.replaceFirst("\\?&", "?"), postgres.getUsername(), postgres.getPassword());
    }

    private String url() {
        String url = postgres.getJdbcUrl();
        return url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema;
    }

    private PostgresSink open(Map<String, String> extra) throws Exception {
        Map<String, String> settings = new HashMap<>(Map.of(
                "url",
                url(),
                "user",
                postgres.getUsername(),
                "password",
                postgres.getPassword(),
                "mode",
                "sessions+events"));
        settings.putAll(extra);
        PostgresSink sink = new PostgresSink();
        sink.open(new SinkContext("pg", 0, settings, ATTRIBUTES));
        return sink;
    }

    private static final byte[] ALICE = {1, 7, 'a', 'l', 'i', 'c', 'e', 8, 6, 100, 64, 0, 10};
    private static final UUID SESSION = new UUID(1, 1);
    /** Recent enough for the default 90-day event retention. */
    private static final long T = System.currentTimeMillis();

    private static ExportEvent event(long n, long position, long commitTime) {
        return new ExportEvent(
                new UUID(9, n),
                position,
                commitTime,
                7,
                1,
                SESSION,
                "s1",
                3,
                ExportEvent.EventOutcome.APPLIED,
                n * 60,
                null,
                n * 10,
                n * 20,
                ALICE);
    }

    private static SessionSnapshot session(
            long version, long seconds, SessionSnapshot.State state, byte[] raw, String id) {
        return new SessionSnapshot(
                SESSION,
                version,
                7,
                id,
                state,
                state == SessionSnapshot.State.STOPPED
                        ? SessionSnapshot.CloseCause.STOP
                        : SessionSnapshot.CloseCause.NONE,
                3,
                seconds,
                seconds * 10,
                seconds * 20,
                T + version,
                version == 100 ? T : null,
                state == SessionSnapshot.State.STOPPED ? T + version : null,
                raw);
    }

    private static Batch batch(
            long epoch, long from, long to, List<ExportEvent> events, List<SessionSnapshot> sessions) {
        return new Batch("pg", epoch, from, to, 0, events, sessions);
    }

    private long count(String sql) throws SQLException {
        try (Connection c = connect(schema);
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private String value(String sql) throws SQLException {
        try (Connection c = connect(schema);
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    @Test
    void sameBatchTwiceChangesNothing() throws Exception {
        try (PostgresSink sink = open(Map.of())) {
            assertThat(sink.storedPosition()).isEqualTo(-1);
            Batch b = batch(
                    1,
                    0,
                    200,
                    List.of(event(1, 100, T), event(2, 200, (T + 60_000))),
                    List.of(session(200, 120, SessionSnapshot.State.ACTIVE, ALICE, "s1")));
            sink.write(b);
            sink.write(b);
            assertThat(sink.storedPosition()).isEqualTo(200);
        }
        assertThat(count("SELECT count(*) FROM accounting_event")).isEqualTo(2);
        assertThat(count("SELECT count(*) FROM accounting_session")).isEqualTo(1);
        assertThat(value("SELECT user_name || ' ' || framed_ip FROM accounting_session"))
                .isEqualTo("alice 100.64.0.10/32");
        assertThat(value("SELECT attributes::text FROM accounting_event LIMIT 1"))
                .isNull(); // only typed attributes
    }

    @Test
    void sessionsOnlyMoveForwardAndClosuresKeepWhatTheyDoNotKnow() throws Exception {
        try (PostgresSink sink = open(Map.of())) {
            sink.write(
                    batch(1, 0, 100, List.of(), List.of(session(100, 0, SessionSnapshot.State.ACTIVE, ALICE, "s1"))));
            sink.write(batch(
                    1, 100, 300, List.of(), List.of(session(300, 180, SessionSnapshot.State.ACTIVE, ALICE, "s1"))));
            sink.write(batch(
                    1, 300, 400, List.of(), List.of(session(200, 60, SessionSnapshot.State.ACTIVE, ALICE, "s1"))));
            assertThat(count("SELECT session_seconds FROM accounting_session"))
                    .as("older version ignored")
                    .isEqualTo(180);
            // a closure (NAS restart) has no session id or attributes
            sink.write(batch(
                    1,
                    400,
                    500,
                    List.of(),
                    List.of(new SessionSnapshot(
                            SESSION,
                            500,
                            7,
                            null,
                            SessionSnapshot.State.STOPPED,
                            SessionSnapshot.CloseCause.NAS_RESTART,
                            3,
                            180L,
                            1800,
                            3600,
                            (T + 900_000),
                            null,
                            (T + 900_000),
                            null))));
        }
        assertThat(value("SELECT acct_session_id || ' ' || user_name || ' ' || state || ' ' || close_cause "
                        + "|| ' ' || (started_at IS NOT NULL) FROM accounting_session"))
                .isEqualTo("s1 alice 2 2 true");
    }

    @Test
    void anOlderEpochIsFenced() throws Exception {
        try (PostgresSink newer = open(Map.of());
                PostgresSink older = open(Map.of())) {
            newer.write(batch(5, 0, 100, List.of(event(1, 100, T)), List.of()));
            assertThatThrownBy(() -> older.write(batch(4, 0, 200, List.of(event(2, 200, T)), List.of())))
                    .isInstanceOf(FencedException.class);
            assertThat(newer.storedPosition()).isEqualTo(100);
        }
        assertThat(count("SELECT count(*) FROM accounting_event"))
                .as("fenced batch rolled back")
                .isEqualTo(1);
    }

    @Test
    void aBrokenConnectionLeavesNothingBehind() throws Exception {
        PostgresSink sink = open(Map.of());
        sink.write(batch(1, 0, 100, List.of(event(1, 100, T)), List.of()));
        try (Connection admin = connect(schema);
                Statement st = admin.createStatement()) {
            st.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    + "WHERE application_name = 'radiusward-exporter-pg'");
        }
        assertThatThrownBy(() -> sink.write(batch(1, 100, 200, List.of(event(2, 200, T)), List.of())))
                .isInstanceOf(SQLException.class);
        sink.close();
        try (PostgresSink reopened = open(Map.of())) {
            assertThat(reopened.storedPosition()).isEqualTo(100);
            reopened.write(batch(1, 100, 200, List.of(event(2, 200, T)), List.of()));
        }
        assertThat(count("SELECT count(*) FROM accounting_event")).isEqualTo(2);
    }

    @Test
    void membersStartingTogetherMigrateOnce() throws Exception {
        List<CompletableFuture<PostgresSink>> opening = List.of(0, 1, 2).stream()
                .map(i -> CompletableFuture.supplyAsync(() -> {
                    try {
                        return open(Map.of());
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                }))
                .toList();
        for (CompletableFuture<PostgresSink> f : opening) {
            f.join().close();
        }
        assertThat(count("SELECT count(*) FROM schema_version")).isEqualTo(1);
    }

    @Test
    void validateAndNoneNeverRunDdl() throws Exception {
        assertThatThrownBy(() -> open(Map.of("schema.manage", "validate")))
                .hasMessageContaining("schema_version is missing");
        assertThat(count("SELECT count(*) FROM information_schema.tables WHERE table_schema = '" + schema + "'"))
                .isZero();
        open(Map.of()).close(); // auto
        try (Connection c = connect(schema);
                Statement st = c.createStatement()) {
            st.execute("UPDATE schema_version SET checksum = 'changed'");
        }
        assertThatThrownBy(() -> open(Map.of("schema.manage", "validate"))).hasMessageContaining("was changed");
        open(Map.of("schema.manage", "none")).close();
    }

    @Test
    void expiredEventPartitionsAreDropped() throws Exception {
        long old = T - 100L * 86_400_000L;
        try (PostgresSink sink = open(Map.of("events.retention", "90d"))) {
            sink.write(batch(1, 0, 100, List.of(event(1, 100, old)), List.of()));
        }
        try (PostgresSink sink = open(Map.of("events.retention", "90d"))) {
            sink.write(batch(1, 100, 200, List.of(event(2, 200, System.currentTimeMillis())), List.of()));
        }
        assertThat(count("SELECT count(*) FROM accounting_event"))
                .as("the 100-day-old event is gone")
                .isEqualTo(1);
        assertThat(count("SELECT count(*) FROM pg_tables WHERE schemaname = '" + schema
                        + "' AND tablename LIKE 'accounting_event_%'"))
                .as("today and two days ahead")
                .isEqualTo(3);
    }

    @Test
    void radacctViewForFreeRadiusTools() throws Exception {
        try (PostgresSink sink = open(Map.of("radacct.view", "true"))) {
            sink.write(
                    batch(1, 0, 100, List.of(), List.of(session(100, 0, SessionSnapshot.State.ACTIVE, ALICE, "s1"))));
        }
        assertThat(value("SELECT acctsessionid || ' ' || username || ' ' || (acctstoptime IS NULL) FROM radacct"))
                .isEqualTo("s1 alice true");
    }
}
