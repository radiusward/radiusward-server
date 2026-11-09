/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.sql;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Users from SQL tables with the FreeRADIUS layout ({@code schema = radcheck}): {@code radcheck} and {@code radreply}
 * (username, attribute, op, value), {@code radusergroup} (username, groupname, priority), {@code radgroupcheck} and
 * {@code radgroupreply} (groupname, attribute, op, value). Read-only: the tables belong to the operator (or an
 * existing FreeRADIUS setup), radiusward never creates or changes them. Four queries per look-up on one pooled
 * connection, each with the query timeout; table names can be changed ({@code table.radcheck}, …).
 */
final class SqlStore implements IdentityStore {

    private static final Logger LOG = LogManager.getLogger(SqlStore.class);

    private final String name;
    private final ConnectionPool pool;
    private final int queryTimeoutSeconds;
    private final String checkSql;
    private final String replySql;
    private final String groupCheckSql;
    private final String groupReplySql;

    SqlStore(StoreContext context) {
        this.name = context.name();
        String schema = context.setting("schema", "radcheck");
        if (!schema.equals("radcheck")) {
            throw new IllegalArgumentException("auth.store." + name + ".schema: only radcheck is supported");
        }
        Duration timeout = context.duration("timeout", "1500ms");
        this.queryTimeoutSeconds = (int) Math.max(1, (timeout.toMillis() + 999) / 1000);
        Properties props = new Properties();
        props.setProperty("user", context.setting("user", ""));
        props.setProperty("password", context.setting("password", ""));
        props.setProperty("connectTimeout", Long.toString(Math.max(1, timeout.toSeconds())));
        props.setProperty("socketTimeout", Long.toString(Math.max(1, timeout.toSeconds() + 1)));
        int size = Integer.parseInt(context.setting("pool", Integer.toString(context.workers())));
        this.pool = new ConnectionPool(context.required("url"), props, size, timeout);
        String check = table(context, "radcheck");
        String reply = table(context, "radreply");
        String userGroup = table(context, "radusergroup");
        String groupCheck = table(context, "radgroupcheck");
        String groupReply = table(context, "radgroupreply");
        this.checkSql = "SELECT attribute, op, value FROM " + check + " WHERE username = ? ORDER BY id";
        this.replySql = "SELECT attribute, op, value FROM " + reply + " WHERE username = ? ORDER BY id";
        this.groupCheckSql = "SELECT g.groupname, c.attribute, c.op, c.value FROM " + userGroup + " g LEFT JOIN "
                + groupCheck + " c ON c.groupname = g.groupname WHERE g.username = ? ORDER BY g.priority, c.id";
        this.groupReplySql = "SELECT g.groupname, r.attribute, r.op, r.value FROM " + userGroup + " g JOIN "
                + groupReply + " r ON r.groupname = g.groupname WHERE g.username = ? ORDER BY g.priority, r.id";
        LOG.info("identity store {}: SQL ({} tables), pool {}, timeout {} ms", name, schema, size, timeout.toMillis());
    }

    private static String table(StoreContext context, String table) {
        String value = context.setting("table." + table, table);
        if (!value.matches("[A-Za-z_][A-Za-z0-9_.]*")) {
            throw new IllegalArgumentException(
                    "auth.store." + context.name() + ".table." + table + ": not a table name");
        }
        return value;
    }

    @Override
    public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
        Connection c;
        try {
            c = pool.borrow();
        } catch (SQLException e) {
            throw new StoreUnavailableException("store " + name + ": " + e.getMessage(), e);
        }
        boolean broken = true;
        try {
            List<AttributeItem> check = items(c, checkSql, userName);
            List<AttributeItem> reply = items(c, replySql, userName);
            Map<String, List<AttributeItem>> groupChecks = groupItems(c, groupCheckSql, userName);
            Map<String, List<AttributeItem>> groupReplies = groupItems(c, groupReplySql, userName);
            broken = false;
            if (check.isEmpty() && reply.isEmpty() && groupChecks.isEmpty()) {
                return Optional.empty();
            }
            List<UserRecord.Group> groups = new ArrayList<>();
            for (Map.Entry<String, List<AttributeItem>> g : groupChecks.entrySet()) {
                groups.add(new UserRecord.Group(
                        g.getKey(), g.getValue(), groupReplies.getOrDefault(g.getKey(), List.of())));
            }
            return Optional.of(new UserRecord(userName, check, reply, groups));
        } catch (SQLException e) {
            throw new StoreUnavailableException("store " + name + ": " + e.getMessage(), e);
        } finally {
            pool.release(c, broken);
        }
    }

    private List<AttributeItem> items(Connection c, String sql, String userName) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(queryTimeoutSeconds);
            ps.setString(1, userName);
            List<AttributeItem> items = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    items.add(new AttributeItem(rs.getString(1), rs.getString(2).trim(), rs.getString(3)));
                }
            }
            return items;
        }
    }

    /** Group name → items, in priority order; a group without items still appears (LEFT JOIN on checks). */
    private Map<String, List<AttributeItem>> groupItems(Connection c, String sql, String userName) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(queryTimeoutSeconds);
            ps.setString(1, userName);
            Map<String, List<AttributeItem>> groups = new LinkedHashMap<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    List<AttributeItem> items = groups.computeIfAbsent(rs.getString(1), k -> new ArrayList<>());
                    if (rs.getString(2) != null) {
                        items.add(new AttributeItem(
                                rs.getString(2), rs.getString(3).trim(), rs.getString(4)));
                    }
                }
            }
            return groups;
        }
    }

    int openConnections() {
        return pool.open();
    }

    @Override
    public void close() {
        pool.close();
    }
}
