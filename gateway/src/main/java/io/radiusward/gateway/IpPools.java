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

    /** The reply attribute of an IPv4 pool. */
    static final String FRAMED_IP = "Framed-IP-Address";

    /** The reply attributes an IPv6 pool may fill (ADR 0059), and the delegated length each allows. */
    static final List<String> IPV6_ATTRIBUTES =
            List.of("Delegated-IPv6-Prefix", "Framed-IPv6-Prefix", "Framed-IPv6-Address");

    /**
     * @param exhausted {@code true}: an Accept without an address when the pool is empty; otherwise a reject
     * @param attribute the reply attribute it fills: {@code Framed-IP-Address} for IPv4 ranges, one of
     *     {@link #IPV6_ATTRIBUTES} for an IPv6 prefix
     * @param prefixes an IPv6 pool's entries ({@code 2001:db8:0:100::/56}); empty for IPv4
     */
    record Pool(
            String name,
            List<long[]> ranges,
            Duration lease,
            boolean exhausted,
            String attribute,
            List<String> prefixes) {

        Pool(String name, List<long[]> ranges, Duration lease, boolean exhausted) {
            this(name, ranges, lease, exhausted, FRAMED_IP, List.of());
        }
    }

    /** Hands out addresses. */
    interface Allocator {
        /** The address for the device as {@code a.b.c.d}, or {@code null} if the pool is empty. */
        String allocate(Pool pool, String user, String device) throws Exception;
    }

    static final String TABLE = "CREATE TABLE IF NOT EXISTS ip_pool (pool text NOT NULL, address inet NOT NULL,"
            + " device text, user_name text, expires_at timestamptz NOT NULL DEFAULT '-infinity',"
            + " PRIMARY KEY (pool, address))";

    /** An entry is taken while an open exported session uses it, or (prefixes) while its holder has one open. */
    private static final String IN_USE = " AND NOT EXISTS (SELECT 1 FROM accounting_session s"
            + " WHERE s.stopped_at IS NULL AND s.calling_station_id IS DISTINCT FROM ?"
            + " AND (s.framed_ip = p.address OR (p.device IS NOT NULL AND s.calling_station_id = p.device)))";

    /** Parameters: pool, device, device, device, device, lease seconds, user, pool. */
    static final String ALLOCATE_SQL = "WITH pick AS (SELECT p.address FROM ip_pool p WHERE p.pool = ?"
            + " AND (p.device = ? OR p.expires_at < now())"
            + IN_USE
            + " ORDER BY (p.device IS NOT DISTINCT FROM ?) DESC, p.expires_at LIMIT 1 FOR UPDATE SKIP LOCKED)"
            + " UPDATE ip_pool p SET device = ?, expires_at = now() + ? * interval '1 second', user_name = ?"
            + " FROM pick WHERE p.pool = ? AND p.address = pick.address RETURNING abbrev(p.address)";

    /** {@link #ALLOCATE_SQL} without the look at {@code accounting_session}: the lease alone holds an address. */
    static final String ALLOCATE_BY_LEASE_SQL =
            ALLOCATE_SQL.replace(IN_USE, " AND (CAST(? AS text) IS NULL OR TRUE)"); // keeps the parameters in place

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
            List<String> prefixes = List.of();
            String attribute = FRAMED_IP;
            String v6 = config.string(prefix + "prefix", "").trim();
            if (!v6.isEmpty()) {
                if (config.has(prefix + "range")) {
                    throw new ConfigException(prefix + "range and " + prefix + "prefix: one or the other");
                }
                attribute = config.string(prefix + "attribute", "Delegated-IPv6-Prefix")
                        .trim();
                if (IPV6_ATTRIBUTES.stream().noneMatch(attribute::equalsIgnoreCase)) {
                    throw new ConfigException(prefix + "attribute: one of " + IPV6_ATTRIBUTES);
                }
                attribute = IPV6_ATTRIBUTES.stream()
                        .filter(attribute::equalsIgnoreCase)
                        .findFirst()
                        .orElseThrow();
                boolean address = attribute.equals("Framed-IPv6-Address");
                int length = config.integer(prefix + "length", address ? 128 : 64);
                if (address && length != 128) {
                    throw new ConfigException(prefix + "length: 128 for Framed-IPv6-Address");
                }
                prefixes = prefixes(prefix, v6, length);
            } else {
                long size = 0;
                for (String range : config.list(prefix + "range", List.of())) {
                    long[] r = range(prefix + "range", range.trim());
                    ranges.add(r);
                    size += r[1] - r[0] + 1;
                }
                if (ranges.isEmpty() || size > MAX_SIZE) {
                    throw new ConfigException(
                            prefix + "range: one or more ranges, " + MAX_SIZE + " addresses at most (or a prefix)");
                }
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
                            exhausted.equals("accept"),
                            attribute,
                            prefixes));
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

    /**
     * The prefixes of length {@code length} in {@code text} ({@code 2001:db8:100::/40}), as {@code address/length};
     * at most {@link #MAX_SIZE}.
     */
    static List<String> prefixes(String key, String text, int length) {
        int slash = text.indexOf('/');
        int bits;
        java.net.InetAddress base;
        try {
            bits = slash < 0 ? -1 : Integer.parseInt(text.substring(slash + 1).trim());
            String literal = slash < 0 ? text : text.substring(0, slash).trim();
            if (!literal.contains(":") || !literal.matches("[0-9A-Fa-f:.]+")) {
                throw new NumberFormatException(literal);
            }
            base = java.net.InetAddress.getByName(literal); // a literal: no DNS look-up
        } catch (NumberFormatException | java.net.UnknownHostException e) {
            throw new ConfigException(key + "prefix: " + text + " is not an IPv6 prefix such as 2001:db8:100::/40", e);
        }
        if (!(base instanceof java.net.Inet6Address) || bits < 1 || bits > 128) {
            throw new ConfigException(key + "prefix: " + text + " is not an IPv6 prefix such as 2001:db8:100::/40");
        }
        if (length < bits || length > 128 || length - bits > 16) {
            throw new ConfigException(
                    key + "length: from the prefix's /" + bits + " to /128, " + MAX_SIZE + " entries at most");
        }
        java.math.BigInteger first = new java.math.BigInteger(1, base.getAddress())
                .shiftRight(128 - bits)
                .shiftLeft(128 - bits);
        java.math.BigInteger step = java.math.BigInteger.ONE.shiftLeft(128 - length);
        int count = 1 << (length - bits);
        List<String> out = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            byte[] raw =
                    first.add(step.multiply(java.math.BigInteger.valueOf(i))).toByteArray();
            byte[] address = new byte[16];
            System.arraycopy(
                    raw, Math.max(0, raw.length - 16), address, Math.max(0, 16 - raw.length), Math.min(16, raw.length));
            try {
                out.add(java.net.InetAddress.getByAddress(address).getHostAddress() + "/" + length);
            } catch (java.net.UnknownHostException e) {
                throw new IllegalStateException(e); // sixteen bytes are always an address
            }
        }
        return List.copyOf(out);
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
                    for (String p : pool.prefixes()) {
                        insert.setString(1, pool.name());
                        insert.setString(2, p);
                        insert.addBatch();
                    }
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
        String query = sessions ? ALLOCATE_SQL : ALLOCATE_BY_LEASE_SQL;
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
