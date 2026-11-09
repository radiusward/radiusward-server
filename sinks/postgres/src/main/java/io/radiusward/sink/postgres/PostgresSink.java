/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.postgres;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.Attributes;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.FencedException;
import io.radiusward.export.SessionSnapshot;
import io.radiusward.export.SinkContext;
import io.radiusward.export.SqlMigrations;
import io.radiusward.export.StorageMode;
import java.io.IOException;
import java.io.StringReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import org.postgresql.PGConnection;
import org.postgresql.copy.CopyManager;

/**
 * PostgreSQL sink (ADR 0018). One transaction per batch:
 *
 * <ol>
 *   <li>lock this sink's row in {@code sink_checkpoint}; a newer epoch there means another exporter owns the
 *       sink: roll back, {@link FencedException};
 *   <li>{@code COPY} the events and the session snapshots into temporary staging tables;
 *   <li>{@code INSERT … ON CONFLICT DO NOTHING} into {@code accounting_event} (insert if absent);
 *   <li>{@code INSERT … ON CONFLICT DO UPDATE … WHERE projection_version <} into {@code accounting_session}
 *       (update only if newer; values a closure does not know are kept);
 *   <li>store position and epoch in {@code sink_checkpoint}; commit.
 * </ol>
 *
 * <p>A batch with a data error is written again row by row under savepoints; rows that still fail go to
 * {@code quarantine}. Settings: {@code url} (required), {@code user}, {@code password}, {@code mode},
 * {@code attributes} ({@code json} | {@code raw} | {@code none}), {@code schema.manage}, {@code events.retention}
 * (default {@code 90d}, {@code 0} keeps everything), {@code sessions.retention} (closed sessions, default
 * {@code 0}: keep), {@code radacct.view} ({@code true} creates a FreeRADIUS-compatible view).
 */
public final class PostgresSink implements AccountingSink {

    private static final String MIGRATIONS = "io/radiusward/sink/postgres/migrations";
    private static final DateTimeFormatter PARTITION = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final long HOUSEKEEPING_INTERVAL_MS = 3_600_000;

    private SinkContext context;
    private Attributes attributes;
    private Connection connection;
    private CopyManager copy;
    private boolean events;
    private String attributeMode;
    private Duration eventsRetention;
    private Duration sessionsRetention;
    private final Set<LocalDate> partitions = new HashSet<>();
    private long nextHousekeepingMs;

    @Override
    public void open(SinkContext context) throws SQLException {
        this.context = context;
        this.attributes = context.attributes();
        this.events = context.mode() == StorageMode.SESSIONS_AND_EVENTS;
        this.attributeMode = context.setting("attributes", "json").toLowerCase(Locale.ROOT);
        if (!List.of("json", "jsonb", "raw", "none").contains(attributeMode)) {
            throw new IllegalArgumentException("sink." + context.name() + ".attributes: expected json, raw or none");
        }
        this.eventsRetention = duration(context.setting("events.retention", "90d"));
        this.sessionsRetention = duration(context.setting("sessions.retention", "0"));
        Properties props = new Properties();
        if (context.settings().containsKey("user")) {
            props.setProperty("user", context.settings().get("user"));
        }
        if (context.settings().containsKey("password")) {
            props.setProperty("password", context.settings().get("password"));
        }
        props.setProperty("ApplicationName", "radiusward-exporter-" + context.name());
        // fail fast when the database is unreachable (the exporter retries with backoff); settings in the URL win
        props.setProperty("connectTimeout", context.setting("connect.timeout.seconds", "5"));
        props.setProperty("socketTimeout", context.setting("socket.timeout.seconds", "120"));
        connection = DriverManager.getConnection(context.required("url"), props);
        SqlMigrations.Manage manage = SqlMigrations.Manage.parse(context.setting("schema.manage", "auto"));
        SqlMigrations.apply(
                connection, migrations(), manage, "SELECT pg_advisory_lock(7101)", "SELECT pg_advisory_unlock(7101)");
        connection.setAutoCommit(false);
        try (Statement st = connection.createStatement()) {
            st.execute(
                    "CREATE TEMP TABLE IF NOT EXISTS staging_session (LIKE accounting_session) ON COMMIT DELETE ROWS");
            st.execute("CREATE TEMP TABLE IF NOT EXISTS staging_event (LIKE accounting_event) ON COMMIT DELETE ROWS");
            if (Boolean.parseBoolean(context.setting("radacct.view", "false")) && manage != SqlMigrations.Manage.NONE) {
                st.execute(RADACCT_VIEW);
            }
        }
        connection.commit();
        copy = connection.unwrap(PGConnection.class).getCopyAPI();
        partitions.clear();
        nextHousekeepingMs = 0;
    }

    /** The schema migrations of this sink (for {@code radiusward admin export-schema}). */
    public static List<SqlMigrations.Migration> migrations() {
        return SqlMigrations.load(PostgresSink.class.getClassLoader(), MIGRATIONS);
    }

    @Override
    public CheckpointStyle checkpointStyle() {
        return CheckpointStyle.TRANSACTIONAL;
    }

    @Override
    public long storedPosition() throws SQLException {
        try (PreparedStatement ps =
                connection.prepareStatement("SELECT position FROM sink_checkpoint WHERE sink = ?")) {
            ps.setString(1, context.name());
            try (ResultSet rs = ps.executeQuery()) {
                long position = rs.next() ? rs.getLong(1) : -1;
                connection.commit();
                return position;
            }
        }
    }

    @Override
    public void write(Batch batch) throws SQLException, IOException, FencedException {
        try {
            fence(batch.epoch());
            List<ExportEvent> rows = events ? batch.events() : List.of();
            try {
                writeRows(rows, batch.sessions());
            } catch (SQLException e) {
                if (!dataError(e)) {
                    throw e;
                }
                rollback();
                fence(batch.epoch());
                writeRowByRow(rows, batch.sessions(), batch.toPosition());
            }
            checkpoint(batch);
            connection.commit();
        } catch (SQLException | IOException | FencedException | RuntimeException e) {
            try {
                rollback();
            } catch (SQLException ignored) {
                // the connection is probably gone; the exporter reopens the sink
            }
            throw e;
        }
        housekeeping();
    }

    /**
     * Rolls back and forgets which partitions exist: partitions created in the rolled-back transaction are gone
     * (they are created again with {@code IF NOT EXISTS} on the next write).
     */
    private void rollback() throws SQLException {
        partitions.clear();
        connection.rollback();
    }

    private void fence(long epoch) throws SQLException, FencedException {
        try (PreparedStatement ps =
                connection.prepareStatement("SELECT epoch FROM sink_checkpoint WHERE sink = ? FOR UPDATE")) {
            ps.setString(1, context.name());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next() && rs.getLong(1) > epoch) {
                    throw new FencedException(
                            "sink_checkpoint has epoch " + rs.getLong(1) + ", this exporter has " + epoch);
                }
            }
        }
    }

    private void writeRows(List<ExportEvent> rows, List<SessionSnapshot> sessions) throws SQLException, IOException {
        if (!rows.isEmpty()) {
            ensurePartitions(rows);
            copy.copyIn("COPY staging_event FROM STDIN", new StringReader(eventText(rows)));
            try (Statement st = connection.createStatement()) {
                st.executeUpdate(INSERT_EVENTS);
            }
        }
        if (!sessions.isEmpty()) {
            copy.copyIn("COPY staging_session FROM STDIN", new StringReader(sessionText(sessions)));
            try (Statement st = connection.createStatement()) {
                st.executeUpdate(UPSERT_SESSIONS);
            }
        }
    }

    /** After a data error: each row on its own savepoint; failures go to quarantine. */
    private void writeRowByRow(List<ExportEvent> rows, List<SessionSnapshot> sessions, long position)
            throws SQLException, IOException {
        ensurePartitions(rows);
        for (ExportEvent e : rows) {
            Savepoint sp = connection.setSavepoint();
            try {
                writeRows(List.of(e), List.of());
                connection.releaseSavepoint(sp);
            } catch (SQLException ex) {
                connection.rollback(sp);
                quarantine(e.logPosition(), ex.getMessage(), "event " + e.eventId());
            }
        }
        for (SessionSnapshot s : sessions) {
            Savepoint sp = connection.setSavepoint();
            try {
                writeRows(List.of(), List.of(s));
                connection.releaseSavepoint(sp);
            } catch (SQLException ex) {
                connection.rollback(sp);
                quarantine(s.projectionVersion(), ex.getMessage(), "session " + s.sessionKey());
            }
        }
    }

    private void quarantine(long position, String reason, String payload) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement(
                "INSERT INTO quarantine (sink, log_position, reason, payload) VALUES (?, ?, ?, ?)")) {
            ps.setString(1, context.name());
            ps.setLong(2, position);
            ps.setString(3, reason);
            ps.setString(4, payload);
            ps.executeUpdate();
        }
    }

    private void checkpoint(Batch batch) throws SQLException {
        try (PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO sink_checkpoint (sink, position, epoch, updated_at) VALUES (?, ?, ?, now())
                ON CONFLICT (sink) DO UPDATE
                SET position = EXCLUDED.position, epoch = EXCLUDED.epoch, updated_at = now()
                WHERE sink_checkpoint.epoch <= EXCLUDED.epoch""")) {
            ps.setString(1, context.name());
            ps.setLong(2, batch.toPosition());
            ps.setLong(3, batch.epoch());
            if (ps.executeUpdate() != 1) {
                throw new SQLException("sink_checkpoint not updated (fenced)");
            }
        }
    }

    private static boolean dataError(SQLException e) {
        return e.getSQLState() != null && e.getSQLState().startsWith("22");
    }

    private void ensurePartitions(List<ExportEvent> rows) throws SQLException {
        for (ExportEvent e : rows) {
            LocalDate day = day(e.commitTime());
            if (!partitions.contains(day)) {
                createPartition(day);
            }
        }
    }

    private void createPartition(LocalDate day) throws SQLException {
        try (Statement st = connection.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS accounting_event_" + PARTITION.format(day)
                    + " PARTITION OF accounting_event FOR VALUES FROM ('" + day + "') TO ('" + day.plusDays(1) + "')");
        }
        partitions.add(day);
    }

    /** Hourly: partitions ahead, expired event partitions and closed sessions removed. */
    private void housekeeping() throws SQLException {
        long now = System.currentTimeMillis();
        if (now < nextHousekeepingMs) {
            return;
        }
        nextHousekeepingMs = now + HOUSEKEEPING_INTERVAL_MS;
        if (events) {
            LocalDate today = day(now);
            for (int d = 0; d <= 2; d++) {
                if (!partitions.contains(today.plusDays(d))) {
                    createPartition(today.plusDays(d));
                }
            }
            connection.commit();
            if (!eventsRetention.isZero()) {
                dropPartitionsBefore(day(now - eventsRetention.toMillis()));
            }
        }
        if (!sessionsRetention.isZero()) {
            try (PreparedStatement ps = connection.prepareStatement("""
                    DELETE FROM accounting_session WHERE session_key IN (
                        SELECT session_key FROM accounting_session WHERE stopped_at < ? LIMIT 10000)""")) {
                ps.setTimestamp(1, new java.sql.Timestamp(now - sessionsRetention.toMillis()));
                while (ps.executeUpdate() > 0) {
                    connection.commit();
                }
            }
            connection.commit();
        }
    }

    private void dropPartitionsBefore(LocalDate cutoff) throws SQLException {
        List<String> expired = new ArrayList<>();
        try (Statement st = connection.createStatement();
                ResultSet rs = st.executeQuery("""
                        SELECT c.relname FROM pg_inherits i
                        JOIN pg_class c ON c.oid = i.inhrelid JOIN pg_class p ON p.oid = i.inhparent
                        JOIN pg_namespace n ON n.oid = p.relnamespace
                        WHERE p.relname = 'accounting_event' AND n.nspname = current_schema()""")) {
            while (rs.next()) {
                String name = rs.getString(1);
                if (name.matches("accounting_event_\\d{8}")
                        && LocalDate.parse(name.substring(name.length() - 8), PARTITION)
                                .isBefore(cutoff)) {
                    expired.add(name);
                }
            }
        }
        connection.commit();
        connection.setAutoCommit(true); // DETACH … CONCURRENTLY cannot run inside a transaction block
        try (Statement st = connection.createStatement()) {
            for (String name : expired) {
                st.execute("ALTER TABLE accounting_event DETACH PARTITION " + name + " CONCURRENTLY");
                st.execute("DROP TABLE " + name);
                partitions.remove(LocalDate.parse(name.substring(name.length() - 8), PARTITION));
            }
        } finally {
            connection.setAutoCommit(false);
        }
    }

    // ---- COPY text format ----------------------------------------------------------------------

    private String eventText(List<ExportEvent> rows) {
        StringBuilder out = new StringBuilder(rows.size() * 400);
        for (ExportEvent e : rows) {
            Attributes.Common c = attributes.common(e.rawAttributes());
            col(out, day(e.commitTime()).toString(), true);
            col(out, e.eventId().toString(), false);
            col(out, Long.toString(e.logPosition()), false);
            col(out, Instant.ofEpochMilli(e.commitTime()).toString(), false);
            col(
                    out,
                    e.eventTimestamp() == null
                            ? null
                            : Instant.ofEpochSecond(e.eventTimestamp()).toString(),
                    false);
            col(out, Integer.toString(e.nasId()), false);
            col(out, Integer.toString(e.gatewayId()), false);
            col(out, e.sessionKey() == null ? null : e.sessionKey().toString(), false);
            col(out, e.acctSessionId(), false);
            col(out, Integer.toString(e.statusType()), false);
            col(out, Integer.toString(e.outcome().ordinal() + 1), false); // 1 applied, 2 stale, 3 merged
            col(out, e.sessionTime() == null ? null : e.sessionTime().toString(), false);
            col(out, Long.toString(e.inputOctets()), false);
            col(out, Long.toString(e.outputOctets()), false);
            col(out, c.userName(), false);
            col(out, c.framedIp(), false);
            col(out, c.nasIp(), false);
            col(out, c.callingStationId(), false);
            col(out, c.terminateCause() == null ? null : c.terminateCause().toString(), false);
            col(out, "0", false);
            col(out, Integer.toString(Attributes.JSON_FORMAT), false);
            col(
                    out,
                    attributeMode.startsWith("json") ? attributes.json(e.rawAttributes(), Attributes.COMMON) : null,
                    false);
            col(out, attributeMode.equals("raw") ? "\\x" + HexFormat.of().formatHex(e.rawAttributes()) : null, false);
            out.append('\n');
        }
        return out.toString();
    }

    private String sessionText(List<SessionSnapshot> sessions) {
        StringBuilder out = new StringBuilder(sessions.size() * 300);
        for (SessionSnapshot s : sessions) {
            Attributes.Common c = attributes.common(s.rawAttributes());
            col(out, s.sessionKey().toString(), true);
            col(out, Integer.toString(s.nasId()), false);
            col(out, s.acctSessionId(), false);
            col(out, c.userName(), false);
            col(out, c.callingStationId(), false);
            col(out, c.framedIp(), false);
            col(out, c.nasIp(), false);
            col(out, s.state() == SessionSnapshot.State.ACTIVE ? "1" : "2", false);
            col(out, Integer.toString(s.closeCause().ordinal()), false);
            col(out, c.terminateCause() == null ? null : c.terminateCause().toString(), false);
            col(out, Integer.toString(s.statusType()), false);
            col(out, s.sessionTime() == null ? null : s.sessionTime().toString(), false);
            col(out, Long.toString(s.inputOctets()), false);
            col(out, Long.toString(s.outputOctets()), false);
            col(
                    out,
                    s.startedAt() == null
                            ? null
                            : Instant.ofEpochMilli(s.startedAt()).toString(),
                    false);
            col(out, Instant.ofEpochMilli(s.lastReceivedAt()).toString(), false);
            col(
                    out,
                    s.stoppedAt() == null
                            ? null
                            : Instant.ofEpochMilli(s.stoppedAt()).toString(),
                    false);
            col(out, "0", false);
            col(out, Long.toString(s.projectionVersion()), false);
            out.append('\n');
        }
        return out.toString();
    }

    /** One column of COPY's text format: tab-separated, {@code \N} for NULL, backslash escapes. */
    private static void col(StringBuilder out, String value, boolean first) {
        if (!first) {
            out.append('\t');
        }
        if (value == null) {
            out.append("\\N");
            return;
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\' -> out.append("\\\\");
                case '\t' -> out.append("\\t");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\0' -> {} // PostgreSQL text cannot hold U+0000
                default -> out.append(ch);
            }
        }
    }

    private static LocalDate day(long epochMillis) {
        return Instant.ofEpochMilli(epochMillis).atZone(ZoneOffset.UTC).toLocalDate();
    }

    static Duration duration(String value) {
        String v = value.trim().toLowerCase(Locale.ROOT);
        if (v.equals("0")) {
            return Duration.ZERO;
        }
        long n = Long.parseLong(v.substring(0, v.length() - 1));
        return switch (v.charAt(v.length() - 1)) {
            case 'd' -> Duration.ofDays(n);
            case 'h' -> Duration.ofHours(n);
            case 'm' -> Duration.ofMinutes(n);
            default -> throw new IllegalArgumentException("expected a duration like 90d, 12h or 0, got " + value);
        };
    }

    @Override
    public void close() {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException ignored) {
                // already broken
            }
            connection = null;
        }
    }

    private static final String INSERT_EVENTS = "INSERT INTO accounting_event SELECT * FROM staging_event "
            + "ON CONFLICT (commit_day, event_id) DO NOTHING";

    private static final String UPSERT_SESSIONS = """
            INSERT INTO accounting_session SELECT * FROM staging_session
            ON CONFLICT (session_key) DO UPDATE SET
                nas_id = EXCLUDED.nas_id,
                acct_session_id = COALESCE(EXCLUDED.acct_session_id, accounting_session.acct_session_id),
                user_name = COALESCE(EXCLUDED.user_name, accounting_session.user_name),
                calling_station_id = COALESCE(EXCLUDED.calling_station_id, accounting_session.calling_station_id),
                framed_ip = COALESCE(EXCLUDED.framed_ip, accounting_session.framed_ip),
                nas_ip = COALESCE(EXCLUDED.nas_ip, accounting_session.nas_ip),
                state = EXCLUDED.state,
                close_cause = EXCLUDED.close_cause,
                terminate_cause = COALESCE(EXCLUDED.terminate_cause, accounting_session.terminate_cause),
                status_type = EXCLUDED.status_type,
                session_seconds = COALESCE(EXCLUDED.session_seconds, accounting_session.session_seconds),
                input_octets = EXCLUDED.input_octets,
                output_octets = EXCLUDED.output_octets,
                started_at = COALESCE(EXCLUDED.started_at, accounting_session.started_at),
                last_received_at = EXCLUDED.last_received_at,
                stopped_at = EXCLUDED.stopped_at,
                quality_flags = EXCLUDED.quality_flags,
                projection_version = EXCLUDED.projection_version
            WHERE accounting_session.projection_version < EXCLUDED.projection_version""";

    /** FreeRADIUS {@code radacct} column names over {@code accounting_session} (read-only). */
    private static final String RADACCT_VIEW = """
            CREATE OR REPLACE VIEW radacct AS SELECT
                session_key::text AS acctuniqueid,
                acct_session_id AS acctsessionid,
                user_name AS username,
                nas_ip AS nasipaddress,
                started_at AS acctstarttime,
                last_received_at AS acctupdatetime,
                stopped_at AS acctstoptime,
                session_seconds AS acctsessiontime,
                input_octets AS acctinputoctets,
                output_octets AS acctoutputoctets,
                calling_station_id AS callingstationid,
                framed_ip AS framedipaddress,
                CASE close_cause WHEN 2 THEN 'NAS-Reboot' WHEN 3 THEN 'Session-Timeout'
                    ELSE terminate_cause::text END AS acctterminatecause
            FROM accounting_session""";
}
