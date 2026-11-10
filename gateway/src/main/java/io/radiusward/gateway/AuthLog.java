/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import io.radiusward.common.management.PrometheusWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The authentication log (ADR 0058): every Access-Accept and Access-Reject decided by this gateway — time, NAS entry,
 * user, Calling-Station-Id, result and, for a reject, its cause — written by a thread of its own to daily JSON-lines
 * files ({@code auth.log.dir}) and/or a PostgreSQL table ({@code auth.log.sql.*}). Workers only offer an entry to a
 * bounded queue: when it is full, or the database fails, entries are dropped and counted, never waited for. Passwords
 * are never logged.
 */
final class AuthLog implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(AuthLog.class);

    record Entry(Instant time, String nas, String user, String station, boolean accepted, String reason) {}

    static final String CREATE_TABLE = "CREATE TABLE IF NOT EXISTS %s (id bigserial PRIMARY KEY,"
            + " authdate timestamptz NOT NULL, nas text NOT NULL, username text, calling_station_id text,"
            + " reply text NOT NULL, reason text)";

    private final ArrayBlockingQueue<Entry> queue;
    private final Path dir;
    private final String url;
    private final Properties properties;
    private final String table;
    private final Thread writer;
    private final AtomicLong written = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private volatile boolean running = true;
    private boolean tableReady;

    AuthLog(int capacity, Path dir, String url, Properties properties, String table) {
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.dir = dir;
        this.url = url;
        this.properties = properties;
        this.table = table;
        this.writer = new Thread(this::run, "auth-log");
        writer.setDaemon(true);
        writer.start();
    }

    /** {@code auth.log.*}; {@code null} without {@code auth.log.dir} or {@code auth.log.sql.url}. */
    static AuthLog from(Config config) {
        String dir = config.string("auth.log.dir", "").trim();
        String url = config.string("auth.log.sql.url", "").trim();
        if (dir.isEmpty() && url.isEmpty()) {
            return null;
        }
        String table = config.string("auth.log.sql.table", "auth_log").trim();
        if (!table.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)?")) {
            throw new ConfigException("auth.log.sql.table: a table name ([schema.]name)");
        }
        int capacity = config.integer("auth.log.queue", 10_000);
        if (capacity < 1) {
            throw new ConfigException("auth.log.queue: at least 1");
        }
        Properties properties = new Properties();
        properties.setProperty("user", config.string("auth.log.sql.user", ""));
        properties.setProperty("password", config.string("auth.log.sql.password", ""));
        return new AuthLog(
                capacity, dir.isEmpty() ? null : Path.of(dir), url.isEmpty() ? null : url, properties, table);
    }

    /** Offers an entry; {@code false} (and counted) if the queue is full. */
    boolean record(Entry entry) {
        if (queue.offer(entry)) {
            return true;
        }
        dropped.incrementAndGet();
        return false;
    }

    private void run() {
        List<Entry> batch = new ArrayList<>();
        while (running || !queue.isEmpty()) {
            try {
                Entry first = queue.poll(200, TimeUnit.MILLISECONDS);
                if (first == null) {
                    continue;
                }
                batch.add(first);
                queue.drainTo(batch, 999);
                write(batch);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                batch.clear();
            }
        }
    }

    private void write(List<Entry> batch) {
        boolean ok = true;
        if (dir != null) {
            ok &= toFiles(batch);
        }
        if (url != null) {
            ok &= toDatabase(batch);
        }
        (ok ? written : failed).addAndGet(batch.size());
    }

    private boolean toFiles(List<Entry> batch) {
        try {
            Files.createDirectories(dir);
            LocalDate day = null;
            Writer out = null;
            try {
                for (Entry e : batch) {
                    LocalDate d = e.time().atZone(ZoneOffset.UTC).toLocalDate();
                    if (!d.equals(day)) {
                        if (out != null) {
                            out.close();
                        }
                        day = d;
                        out = Files.newBufferedWriter(
                                dir.resolve("auth-" + d + ".jsonl"),
                                StandardCharsets.UTF_8,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.APPEND);
                    }
                    out.write(json(e));
                    out.write('\n');
                }
            } finally {
                if (out != null) {
                    out.close();
                }
            }
            return true;
        } catch (IOException e) {
            LOG.warn("auth log: writing to {} failed, {} entries lost: {}", dir, batch.size(), e.toString());
            return false;
        }
    }

    private boolean toDatabase(List<Entry> batch) {
        try (Connection c = DriverManager.getConnection(url, properties)) {
            if (!tableReady) {
                try (Statement s = c.createStatement()) {
                    s.execute(CREATE_TABLE.formatted(table));
                }
                tableReady = true;
            }
            try (PreparedStatement s = c.prepareStatement("INSERT INTO " + table
                    + " (authdate, nas, username, calling_station_id, reply, reason) VALUES (?, ?, ?, ?, ?, ?)")) {
                for (Entry e : batch) {
                    s.setTimestamp(1, Timestamp.from(e.time()));
                    s.setString(2, e.nas());
                    s.setString(3, e.user());
                    s.setString(4, e.station());
                    s.setString(5, e.accepted() ? "Access-Accept" : "Access-Reject");
                    s.setString(6, e.reason());
                    s.addBatch();
                }
                s.executeBatch();
            }
            return true;
        } catch (SQLException e) {
            LOG.warn("auth log: the database failed, {} entries lost: {}", batch.size(), e.toString());
            return false;
        }
    }

    static String json(Entry e) {
        return "{\"time\":" + CoaApi.quote(e.time().toString()) + ",\"nas\":" + CoaApi.quote(e.nas())
                + ",\"user\":" + CoaApi.quote(e.user()) + ",\"station\":" + CoaApi.quote(e.station())
                + ",\"result\":\"" + (e.accepted() ? "accept" : "reject") + "\""
                + (e.reason() == null ? "" : ",\"reason\":" + CoaApi.quote(e.reason())) + "}";
    }

    long written() {
        return written.get();
    }

    long dropped() {
        return dropped.get();
    }

    long failed() {
        return failed.get();
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter("radiusward_gateway_auth_log_entries_total", "Authentication log entries (ADR 0058)");
        w.sample(written(), "gateway", gateway, "result", "written");
        w.sample(dropped(), "gateway", gateway, "result", "dropped");
        w.sample(failed(), "gateway", gateway, "result", "failed");
    }

    /** Writes what is queued, then stops. */
    @Override
    public void close() {
        running = false;
        try {
            writer.join(5_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
