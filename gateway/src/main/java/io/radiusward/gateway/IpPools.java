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
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * IPv4 address pools (ADR 0050): a user or group with {@code Pool-Name := <pool>} gets a {@code Framed-IP-Address} from
 * the pool's table in PostgreSQL. An address is free when its lease (the time until the session's Accounting-Start is
 * exported) ran out and no open session in the exported {@code accounting_session} uses it; release thus follows
 * accounting. A device (Calling-Station-Id, else the user) gets its previous address again while it is free.
 */
final class IpPools {

    private static final Logger LOG = LogManager.getLogger(IpPools.class);

    /** The largest pool, in addresses. */
    static final int MAX_SIZE = 65536;

    /**
     * @param exhausted {@code true}: an Accept without an address when the pool is empty; otherwise a reject
     */
    record Pool(String name, List<long[]> ranges, Duration lease, boolean exhausted) {}

    /** Hands out addresses. */
    interface Allocator {
        /** The address for the device as {@code a.b.c.d}, or {@code null} if the pool is empty. */
        String allocate(Pool pool, String user, String device) throws Exception;
    }

    static final String TABLE = "CREATE TABLE IF NOT EXISTS ip_pool (pool text NOT NULL, address inet NOT NULL,"
            + " device text, user_name text, expires_at timestamptz NOT NULL DEFAULT '-infinity',"
            + " PRIMARY KEY (pool, address))";

    /** Parameters: pool, device, device, device, lease seconds, user, pool. */
    static final String ALLOCATE = "WITH pick AS (SELECT p.address FROM ip_pool p WHERE p.pool = ?"
            + " AND (p.device = ? OR p.expires_at < now())"
            + " AND NOT EXISTS (SELECT 1 FROM accounting_session s WHERE s.stopped_at IS NULL"
            + " AND s.framed_ip = p.address AND s.calling_station_id IS DISTINCT FROM ?)"
            + " ORDER BY (p.device IS NOT DISTINCT FROM ?) DESC, p.expires_at LIMIT 1 FOR UPDATE SKIP LOCKED)"
            + " UPDATE ip_pool p SET device = ?, expires_at = now() + ? * interval '1 second', user_name = ?"
            + " FROM pick WHERE p.pool = ? AND p.address = pick.address RETURNING host(p.address)";

    /** {@link #ALLOCATE} without the look at {@code accounting_session}: the lease alone holds an address. */
    static final String ALLOCATE_BY_LEASE = ALLOCATE.replace(
            " AND NOT EXISTS (SELECT 1 FROM accounting_session s WHERE s.stopped_at IS NULL"
                    + " AND s.framed_ip = p.address AND s.calling_station_id IS DISTINCT FROM ?)",
            " AND (CAST(? AS text) IS NULL OR TRUE)"); // keeps the parameters in place

    private final Map<String, Pool> pools;
    private final Allocator allocator;

    IpPools(Map<String, Pool> pools, Allocator allocator) {
        this.pools = Map.copyOf(pools);
        this.allocator = allocator;
    }

    Pool pool(String name) {
        return pools.get(name.trim());
    }

    String allocate(Pool pool, String user, String device) throws Exception {
        return allocator.allocate(pool, user, device);
    }

    /** {@code auth.pools} and {@code auth.pool.*}; {@code null} without pools. Creates and fills the table. */
    static IpPools from(Config config) {
        List<String> names = config.list("auth.pools", List.of());
        if (names.isEmpty()) {
            return null;
        }
        Map<String, Pool> pools = new LinkedHashMap<>();
        for (String raw : names) {
            String name = raw.trim();
            String prefix = "auth.pool." + name + ".";
            List<long[]> ranges = new ArrayList<>();
            long size = 0;
            for (String range : config.list(prefix + "range", List.of())) {
                long[] r = range(prefix + "range", range.trim());
                ranges.add(r);
                size += r[1] - r[0] + 1;
            }
            if (ranges.isEmpty() || size > MAX_SIZE) {
                throw new ConfigException(prefix + "range: one or more ranges, " + MAX_SIZE + " addresses at most");
            }
            String exhausted =
                    config.string(prefix + "exhausted", "reject").trim().toLowerCase(Locale.ROOT);
            if (!exhausted.equals("reject") && !exhausted.equals("accept")) {
                throw new ConfigException(prefix + "exhausted: reject or accept");
            }
            pools.put(
                    name,
                    new Pool(
                            name,
                            List.copyOf(ranges),
                            config.duration(prefix + "lease", Duration.ofMinutes(5)),
                            exhausted.equals("accept")));
        }
        Properties properties = new Properties();
        properties.setProperty("user", config.string("auth.pool.sql.user", ""));
        properties.setProperty("password", config.string("auth.pool.sql.password", ""));
        String url = config.string("auth.pool.sql.url");
        boolean sessions = config.bool("auth.pool.sessions", true);
        try {
            fill(url, properties, pools.values());
        } catch (SQLException e) {
            // the database may come later; allocations fail (no answer) until the table exists
            LOG.warn("IP pools: could not prepare the table: {}", e.toString());
        }
        return new IpPools(pools, sql(url, properties, sessions));
    }

    /** {@code a.b.c.d-e.f.g.h}, {@code a.b.c.d/n} or one address; as {first, last}. */
    static long[] range(String key, String text) {
        try {
            int dash = text.indexOf('-');
            if (dash > 0) {
                long first = ipv4(text.substring(0, dash).trim());
                long last = ipv4(text.substring(dash + 1).trim());
                if (last < first) {
                    throw new ConfigException(key + ": " + text + " ends before it starts");
                }
                return new long[] {first, last};
            }
            int slash = text.indexOf('/');
            if (slash > 0) {
                int bits = Integer.parseInt(text.substring(slash + 1).trim());
                if (bits < 16 || bits > 32) {
                    throw new ConfigException(key + ": " + text + ": prefix from /16 to /32");
                }
                long base = ipv4(text.substring(0, slash).trim()) & (0xFFFFFFFFL << (32 - bits)) & 0xFFFFFFFFL;
                long last = base + (1L << (32 - bits)) - 1;
                return bits >= 31 ? new long[] {base, last} : new long[] {base + 1, last - 1}; // no network, broadcast
            }
            long one = ipv4(text);
            return new long[] {one, one};
        } catch (NumberFormatException e) {
            throw new ConfigException(key + ": " + text + " is not an IPv4 range", e);
        }
    }

    private static long ipv4(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            throw new NumberFormatException(text);
        }
        long value = 0;
        for (String part : parts) {
            int octet = Integer.parseInt(part);
            if (octet < 0 || octet > 255 || part.length() > 3) {
                throw new NumberFormatException(text);
            }
            value = value << 8 | octet;
        }
        return value;
    }

    static String text(long address) {
        return (address >>> 24 & 0xFF) + "." + (address >>> 16 & 0xFF) + "." + (address >>> 8 & 0xFF) + "."
                + (address & 0xFF);
    }

    /** Creates {@code ip_pool} if missing and adds the pools' addresses (existing rows and leases stay). */
    static void fill(String url, Properties properties, Iterable<Pool> pools) throws SQLException {
        try (Connection c = DriverManager.getConnection(url, properties)) {
            try (Statement s = c.createStatement()) {
                s.execute(TABLE);
            }
            c.setAutoCommit(false);
            try (PreparedStatement insert = c.prepareStatement(
                    "INSERT INTO ip_pool (pool, address) VALUES (?, CAST(? AS inet)) ON CONFLICT DO NOTHING")) {
                for (Pool pool : pools) {
                    for (long[] r : pool.ranges()) {
                        for (long a = r[0]; a <= r[1]; a++) {
                            insert.setString(1, pool.name());
                            insert.setString(2, text(a));
                            insert.addBatch();
                        }
                    }
                }
                insert.executeBatch();
            }
            c.commit();
        }
    }

    static Allocator sql(String url, Properties properties, boolean sessions) {
        String query = sessions ? ALLOCATE : ALLOCATE_BY_LEASE;
        return (pool, user, device) -> {
            try (Connection c = DriverManager.getConnection(url, properties);
                    PreparedStatement s = c.prepareStatement(query)) {
                s.setQueryTimeout(5);
                s.setString(1, pool.name());
                s.setString(2, device);
                s.setString(3, device);
                s.setString(4, device);
                s.setString(5, device);
                s.setLong(6, Math.max(1, pool.lease().toSeconds()));
                s.setString(7, user);
                s.setString(8, pool.name());
                try (ResultSet r = s.executeQuery()) {
                    return r.next() ? r.getString(1) : null;
                }
            }
        };
    }
}
