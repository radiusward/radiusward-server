/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A small versioned migration runner for relational sinks (decision 6 of the Phase 3 plan; no Flyway).
 *
 * <p>Migrations are plain SQL files with Flyway-style names ({@code V1__init.sql}) in a class-path directory,
 * listed in order in {@code <dir>/migrations.txt}. Each is applied in its own transaction and recorded with
 * its SHA-256 in {@code schema_version}; a changed file is an error. A statement ends with {@code ;} at the end
 * of a line. Concurrent members are serialised by a database lock supplied by the dialect.
 */
public final class SqlMigrations {

    /** {@code schema.manage}. */
    public enum Manage {
        /** apply missing migrations */
        AUTO,
        /** only check that every migration is applied and unchanged; never run DDL */
        VALIDATE,
        /** do nothing (a DBA manages the schema from {@code radiusward admin export-schema}) */
        NONE;

        public static Manage parse(String value) {
            return switch (value.trim().toLowerCase(Locale.ROOT)) {
                case "auto" -> AUTO;
                case "validate" -> VALIDATE;
                case "none" -> NONE;
                default ->
                    throw new IllegalArgumentException("schema.manage: expected auto, validate or none, got " + value);
            };
        }
    }

    /** One migration file. */
    public record Migration(int version, String name, String sql, String checksum) {}

    private SqlMigrations() {}

    /** The migrations under {@code dir} on {@code loader}'s class path, in order. */
    public static List<Migration> load(ClassLoader loader, String dir) {
        List<Migration> migrations = new ArrayList<>();
        for (String name :
                read(loader, dir + "/migrations.txt").lines().map(String::trim).toList()) {
            if (name.isEmpty() || name.startsWith("#")) {
                continue;
            }
            if (!name.matches("V\\d+__[A-Za-z0-9_]+\\.sql")) {
                throw new IllegalStateException("migration name must look like V1__init.sql: " + name);
            }
            int version = Integer.parseInt(name.substring(1, name.indexOf("__")));
            if (!migrations.isEmpty()
                    && version <= migrations.get(migrations.size() - 1).version()) {
                throw new IllegalStateException("migrations out of order at " + name);
            }
            String sql = read(loader, dir + "/" + name);
            migrations.add(new Migration(version, name, sql, sha256(sql)));
        }
        return migrations;
    }

    /**
     * Applies or validates {@code migrations}.
     *
     * @param lock SQL that takes an exclusive session-level lock, e.g. {@code SELECT pg_advisory_lock(7101)}
     * @param unlock SQL that releases it
     */
    public static void apply(
            Connection connection, List<Migration> migrations, Manage manage, String lock, String unlock)
            throws SQLException {
        if (manage == Manage.NONE) {
            return;
        }
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(true);
        try (Statement st = connection.createStatement()) {
            st.execute(lock);
            try {
                if (manage == Manage.AUTO) {
                    st.execute("CREATE TABLE IF NOT EXISTS schema_version (version integer PRIMARY KEY, "
                            + "name text NOT NULL, checksum text NOT NULL, applied_at timestamp NOT NULL)");
                }
                Map<Integer, String> applied = applied(connection, manage);
                for (Migration m : migrations) {
                    String checksum = applied.get(m.version());
                    if (checksum != null) {
                        if (!checksum.equals(m.checksum())) {
                            throw new SQLException("migration " + m.name() + " was changed after it was applied "
                                    + "(checksum " + checksum + " in schema_version, " + m.checksum() + " now)");
                        }
                        continue;
                    }
                    if (manage == Manage.VALIDATE) {
                        throw new SQLException("schema is behind: migration " + m.name() + " is not applied "
                                + "(schema.manage=validate; apply it from radiusward admin export-schema)");
                    }
                    run(connection, m);
                }
            } finally {
                st.execute(unlock);
            }
        } finally {
            connection.setAutoCommit(autoCommit);
        }
    }

    private static Map<Integer, String> applied(Connection connection, Manage manage) throws SQLException {
        Map<Integer, String> applied = new HashMap<>();
        try (Statement st = connection.createStatement();
                ResultSet rs = st.executeQuery("SELECT version, checksum FROM schema_version")) {
            while (rs.next()) {
                applied.put(rs.getInt(1), rs.getString(2));
            }
        } catch (SQLException e) {
            if (manage == Manage.VALIDATE) {
                throw new SQLException("schema_version is missing (schema.manage=validate)", e);
            }
            throw e;
        }
        return applied;
    }

    private static void run(Connection connection, Migration m) throws SQLException {
        connection.setAutoCommit(false);
        try (Statement st = connection.createStatement()) {
            for (String statement : statements(m.sql())) {
                st.execute(statement);
            }
            try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)")) {
                insert.setInt(1, m.version());
                insert.setString(2, m.name());
                insert.setString(3, m.checksum());
                insert.setTimestamp(4, new java.sql.Timestamp(System.currentTimeMillis()));
                insert.executeUpdate();
            }
            connection.commit();
        } catch (SQLException e) {
            connection.rollback();
            throw new SQLException("migration " + m.name() + " failed: " + e.getMessage(), e);
        } finally {
            connection.setAutoCommit(true);
        }
    }

    /** The full SQL a DBA would run: every migration plus its {@code schema_version} row. */
    public static String script(List<Migration> migrations) {
        StringBuilder out = new StringBuilder();
        out.append("CREATE TABLE IF NOT EXISTS schema_version (version integer PRIMARY KEY, name text NOT NULL, ")
                .append("checksum text NOT NULL, applied_at timestamp NOT NULL);\n\n");
        for (Migration m : migrations) {
            out.append("-- ")
                    .append(m.name())
                    .append('\n')
                    .append(m.sql().strip())
                    .append('\n');
            out.append("INSERT INTO schema_version (version, name, checksum, applied_at) VALUES (")
                    .append(m.version())
                    .append(", '")
                    .append(m.name())
                    .append("', '")
                    .append(m.checksum())
                    .append("', CURRENT_TIMESTAMP);\n\n");
        }
        return out.toString();
    }

    static List<String> statements(String sql) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String line : sql.lines().toList()) {
            String trimmed = line.strip();
            if (trimmed.startsWith("--") && current.isEmpty()) {
                continue;
            }
            current.append(line).append('\n');
            if (trimmed.endsWith(";")) {
                String statement = current.toString().strip();
                statements.add(statement.substring(0, statement.length() - 1));
                current.setLength(0);
            }
        }
        if (!current.toString().isBlank()) {
            statements.add(current.toString().strip());
        }
        return statements;
    }

    private static String read(ClassLoader loader, String resource) {
        try (InputStream in = loader.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("missing resource " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String sha256(String sql) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(sql.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
