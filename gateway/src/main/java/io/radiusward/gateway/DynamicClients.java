/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLongArray;
import org.agrona.collections.Int2ObjectHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * NAS entries loaded on demand (ADR 0046): a packet from an address no configured entry covers, inside
 * {@code nas.dynamic.networks}, asks a background thread to look the address up in a source (SQL, the {@code nas}
 * table layout other servers use: {@code nasname}, {@code shortname}, {@code secret}, {@code type}). That packet is
 * dropped — the NAS sends it again — and once the entry is found, packets from the address use it until
 * {@code nas.dynamic.lifetime} passes; then it is looked up again. An address the source does not know is not asked
 * for again before {@code nas.dynamic.negative.ttl}. The packet path reads a copy-on-write table without locks or
 * allocation; only the background thread writes, and nothing on the packet path ever waits for the source.
 */
public final class DynamicClients implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(DynamicClients.class);

    /** One row of the source; {@code type} may be {@code null}. */
    public record Row(String nasname, String shortname, byte[] secret, String type) {}

    /** Where entries come from: the row of an address, {@code null} if there is none. */
    @FunctionalInterface
    public interface Source {
        Row lookup(InetAddress address) throws Exception;
    }

    enum Counter {
        LOOKUPS,
        FOUND,
        NOT_FOUND,
        FAILED,
        QUEUE_FULL,
        EXPIRED
    }

    private record Entry(NasClient client, long expiresAt) {}

    private final int[][] networks; // address, prefix length
    private final Source source;
    private final long lifetimeMillis;
    private final long negativeMillis;
    private final int max;
    private final ArrayBlockingQueue<Integer> queue = new ArrayBlockingQueue<>(1024);
    private final Set<Integer> pending = ConcurrentHashMap.newKeySet();
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    private volatile Int2ObjectHashMap<Entry> found = new Int2ObjectHashMap<>();
    private volatile Int2ObjectHashMap<Long> missing = new Int2ObjectHashMap<>();
    private final Thread thread;
    private volatile boolean closed;

    /**
     * @param networks the networks (address, prefix length) whose unknown addresses are looked up
     * @param max entries held at once; beyond it no more are added until some expire
     */
    DynamicClients(List<int[]> networks, Source source, Duration lifetime, Duration negativeTtl, int max) {
        this.networks = networks.toArray(int[][]::new);
        this.source = source;
        this.lifetimeMillis = lifetime.toMillis();
        this.negativeMillis = negativeTtl.toMillis();
        this.max = max;
        this.thread = new Thread(this::run, "nas-dynamic");
        thread.setDaemon(true);
        thread.start();
    }

    /** {@code nas.dynamic.*}, or {@code null} when it is off. */
    static DynamicClients from(Config config) {
        if (!config.bool("nas.dynamic.enabled", false)) {
            return null;
        }
        List<int[]> networks = new ArrayList<>();
        for (String network : config.list("nas.dynamic.networks")) {
            String n = network.trim();
            int slash = n.indexOf('/');
            int prefix = slash < 0 ? 32 : Integer.parseInt(n.substring(slash + 1));
            if (prefix < 8 || prefix > 32) {
                throw new ConfigException("nas.dynamic.networks: prefix 8 to 32, got " + n);
            }
            networks.add(new int[] {
                NasRegistry.ipv4("nas.dynamic.networks", slash < 0 ? n : n.substring(0, slash)), prefix
            });
        }
        if (networks.isEmpty()) {
            throw new ConfigException("nas.dynamic.networks: required, the networks whose NAS are looked up");
        }
        String url = config.string("nas.dynamic.sql.url");
        Properties properties = new Properties();
        properties.setProperty("user", config.string("nas.dynamic.sql.user", ""));
        properties.setProperty("password", config.string("nas.dynamic.sql.password", ""));
        String query = config.string(
                "nas.dynamic.sql.query", "SELECT nasname, shortname, secret, type FROM nas WHERE nasname = ?");
        int max = config.integer("nas.dynamic.max", 10_000);
        if (max < 1) {
            throw new ConfigException("nas.dynamic.max: at least 1");
        }
        return new DynamicClients(
                networks,
                sql(url, properties, query),
                config.duration("nas.dynamic.lifetime", Duration.ofHours(1)),
                config.duration("nas.dynamic.negative.ttl", Duration.ofMinutes(1)),
                max);
    }

    /** A source over JDBC: the query gets the address as text and returns nasname, shortname, secret, type. */
    static Source sql(String url, Properties properties, String query) {
        return address -> {
            try (Connection c = DriverManager.getConnection(url, properties);
                    PreparedStatement s = c.prepareStatement(query)) {
                s.setQueryTimeout(5);
                s.setString(1, address.getHostAddress());
                try (ResultSet r = s.executeQuery()) {
                    if (!r.next()) {
                        return null;
                    }
                    String secret = r.getString(3);
                    return new Row(
                            r.getString(1),
                            r.getString(2),
                            secret == null ? null : secret.getBytes(StandardCharsets.UTF_8),
                            r.getString(4));
                }
            }
        };
    }

    /**
     * The loaded entry of an address, if it is fresh; otherwise {@code null}, and a lookup is asked for when the
     * address is in a dynamic network and not known to be missing. Called on the packet path: no lock, no allocation
     * for a loaded entry.
     */
    NasClient find(int address, long nowMillis) {
        Entry e = found.get(address);
        if (e != null && nowMillis < e.expiresAt()) {
            return e.client();
        }
        if (!inNetworks(address)) {
            return null;
        }
        Long until = missing.get(address);
        if (until != null && nowMillis < until) {
            return null;
        }
        if (pending.add(address)) {
            if (!queue.offer(address)) {
                pending.remove(address);
                counts.incrementAndGet(Counter.QUEUE_FULL.ordinal());
            }
        }
        return null;
    }

    private boolean inNetworks(int address) {
        for (int[] n : networks) {
            int mask = n[1] == 0 ? 0 : -1 << (32 - n[1]);
            if ((address & mask) == (n[0] & mask)) {
                return true;
            }
        }
        return false;
    }

    private void run() {
        while (!closed) {
            Integer address;
            try {
                address = queue.poll(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); // closing: the flag stays for whoever asked
                return;
            }
            if (address == null) {
                expire(System.currentTimeMillis());
                continue;
            }
            try {
                lookup(address);
            } finally {
                pending.remove(address);
            }
        }
    }

    private void lookup(int address) {
        counts.incrementAndGet(Counter.LOOKUPS.ordinal());
        long now = System.currentTimeMillis();
        InetAddress ip = NasRegistry.inet(address);
        Row row;
        try {
            row = source.lookup(ip);
        } catch (Exception e) {
            counts.incrementAndGet(Counter.FAILED.ordinal());
            LOG.warn("dynamic NAS lookup of {} failed: {}", ip.getHostAddress(), e.toString());
            return; // asked again with the next packet
        }
        if (row == null || row.secret() == null || row.secret().length == 0) {
            counts.incrementAndGet(Counter.NOT_FOUND.ordinal());
            Int2ObjectHashMap<Long> next = new Int2ObjectHashMap<>(missing);
            next.put(address, Long.valueOf(now + negativeMillis));
            missing = next;
            return;
        }
        if (found.size() >= max && !found.containsKey(address)) {
            expire(now);
            if (found.size() >= max) {
                LOG.warn("nas.dynamic.max reached: {} not added", ip.getHostAddress());
                return;
            }
        }
        String name = "dynamic:"
                + (row.shortname() == null || row.shortname().isBlank() ? ip.getHostAddress() : row.shortname());
        NasClient client = new NasClient(
                name,
                NasRegistry.fnv1a("dynamic:" + ip.getHostAddress()), // the same on every gateway
                address,
                32,
                row.secret(),
                row.type() == null || row.type().isBlank()
                        ? "default"
                        : row.type().trim().toLowerCase(Locale.ROOT),
                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                new NasClient.Identity[0],
                0,
                NasClient.MessageAuthenticatorPolicy.REQUIRED);
        Int2ObjectHashMap<Entry> next = new Int2ObjectHashMap<>(found);
        next.put(address, new Entry(client, now + lifetimeMillis));
        found = next;
        if (missing.containsKey(address)) {
            Int2ObjectHashMap<Long> m = new Int2ObjectHashMap<>(missing);
            m.remove(address);
            missing = m;
        }
        counts.incrementAndGet(Counter.FOUND.ordinal());
        LOG.info("dynamic NAS {} ({}) loaded", name, ip.getHostAddress());
    }

    /** Drops entries past their lifetime and misses past their TTL. */
    private void expire(long now) {
        boolean stale = false;
        for (Entry e : found.values()) {
            stale |= now >= e.expiresAt();
        }
        if (stale) {
            Int2ObjectHashMap<Entry> next = new Int2ObjectHashMap<>(found);
            int before = next.size();
            next.values().removeIf(e -> now >= e.expiresAt());
            counts.addAndGet(Counter.EXPIRED.ordinal(), before - next.size());
            found = next;
        }
        boolean old = false;
        for (Long until : missing.values()) {
            old |= now >= until;
        }
        if (old) {
            Int2ObjectHashMap<Long> next = new Int2ObjectHashMap<>(missing);
            next.values().removeIf(until -> now >= until);
            missing = next;
        }
    }

    long get(Counter counter) {
        return counts.get(counter.ordinal());
    }

    int size() {
        return found.size();
    }

    void writeMetrics(io.radiusward.common.management.PrometheusWriter w, String gateway) {
        w.counter("radiusward_gateway_nas_dynamic_total", "NAS entries looked up on demand (nas.dynamic.*)");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
        }
        w.gauge("radiusward_gateway_nas_dynamic_entries", "Dynamic NAS entries loaded")
                .sample(size(), "gateway", gateway);
    }

    @Override
    public void close() {
        closed = true;
        thread.interrupt();
    }
}
