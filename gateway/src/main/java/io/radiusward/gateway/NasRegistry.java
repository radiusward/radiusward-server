/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.agrona.collections.Int2ObjectHashMap;

/**
 * The configured NAS clients, looked up by source address. IPv4 exact matches are allocation-free
 * ({@code Inet4Address.hashCode()} is the address); CIDR ranges are scanned in configuration order. The entry (and
 * its secret) always comes from the source address; attributes in the packet only tell apart the devices behind one
 * entry when {@code identity} is set (ADR 0019).
 *
 * <pre>
 * nas.core.address = 10.255.0.1          # or a CIDR range: 10.0.0.0/24
 * nas.core.secret  = ${env:NAS_CORE_SECRET}
 * nas.core.vendor  = mikrotik
 * nas.core.message-authenticator = optional   # required | optional | off
 * nas.core.id      = 1001                # optional, defaults to a hash of the name
 * nas.core.identity = source-ip          # or e.g. nas-identifier, called-station-id (devices behind NAT)
 * nas.core.idle.timeout = 15m            # close sessions without an event for this long (≈ 3 interims)
 * nas.core.access.message-authenticator = required   # on Access-Requests (default required: BlastRADIUS)
 * </pre>
 *
 * An entry without {@code address} but with {@code radsec = true} and {@code radsec.identity} (or {@code dtls = true}
 * and {@code dtls.identity}) is identified by its RadSec or DTLS client certificate alone (NAT, changing addresses);
 * it is kept out of the address lookup.
 */
public final class NasRegistry {

    /** The configured entries; replaced as a whole when the configuration is reloaded (ADR 0054). */
    private static final class Table {
        final Int2ObjectHashMap<NasClient> exact = new Int2ObjectHashMap<>();
        NasClient[] ranges;
        NasClient[] ranges6; // IPv6 entries, longest prefix first
        List<NasClient> all;
        // the last IPv6 sender and its entry: the JDK hands out the same address object for a repeating sender
        volatile Inet6Address lastAddress6;
        volatile NasClient lastClient6;
    }

    private volatile Table table;
    private volatile DynamicClients dynamic; // entries looked up on demand (ADR 0046), after the configured ones

    private NasRegistry(List<NasClient> clients) {
        this.table = table(clients);
    }

    private static Table table(List<NasClient> clients) {
        Table t = new Table();
        Int2ObjectHashMap<NasClient> exact = t.exact;
        List<NasClient> rangeList = new ArrayList<>();
        List<NasClient> range6List = new ArrayList<>();
        Map<Integer, String> ids = new HashMap<>();
        for (NasClient c : clients) {
            String other = ids.put(c.id(), c.name());
            if (other != null) {
                throw new ConfigException("nas." + c.name() + ".id: id " + c.id() + " already used by nas." + other
                        + "; set nas.<name>.id explicitly");
            }
            if (c.certificateOnly()) {
                continue; // found by certificate, never by address
            }
            if (c.ipv6()) {
                for (NasClient earlier : range6List) {
                    if (earlier.prefixLength() == c.prefixLength()
                            && java.util.Arrays.equals(earlier.network6(), c.network6())) {
                        throw new ConfigException("nas." + c.name() + ".address: duplicate address");
                    }
                }
                range6List.add(c);
                continue;
            }
            if (c.prefixLength() == 32) {
                if (exact.put(c.network(), c) != null) {
                    throw new ConfigException("nas." + c.name() + ".address: duplicate address");
                }
            } else {
                rangeList.add(c);
            }
        }
        t.ranges = rangeList.toArray(NasClient[]::new);
        range6List.sort((a, b) -> Integer.compare(b.prefixLength(), a.prefixLength()));
        t.ranges6 = range6List.toArray(NasClient[]::new);
        t.all = List.copyOf(clients);
        return t;
    }

    /**
     * Takes the configured entries of {@code other} (a registry from a reloaded configuration, ADR 0054); entries looked
     * up on demand stay. Requests already received keep the entry they arrived with.
     */
    void replace(NasRegistry other) {
        this.table = other.table;
    }

    public static NasRegistry of(List<NasClient> clients) {
        return new NasRegistry(clients);
    }

    private static boolean byCertificate(Config config, String prefix, String transport) {
        return config.bool(prefix + transport, false)
                && !config.string(prefix + transport + ".identity", "").isBlank();
    }

    public static NasRegistry from(Config config) {
        NasRegistry registry = configured(config);
        DynamicClients dynamic = DynamicClients.from(config);
        if (registry.clients().isEmpty() && dynamic == null) {
            throw new ConfigException("no NAS configured: add nas.<name>.address and nas.<name>.secret");
        }
        registry.dynamic(dynamic);
        return registry;
    }

    /** The configured entries alone, without {@code nas.dynamic.*} (a reload keeps the running lookups). */
    static NasRegistry configured(Config config) {
        List<NasClient> clients = new ArrayList<>();
        for (String name : config.names("nas")) {
            if (name.equals("dynamic")) {
                continue; // nas.dynamic.*: entries looked up on demand, not one entry
            }
            String prefix = "nas." + name + ".";
            String address = config.string(prefix + "address", "").trim();
            boolean byCertificate = address.isEmpty();
            if (byCertificate && !byCertificate(config, prefix, "radsec") && !byCertificate(config, prefix, "dtls")) {
                throw new ConfigException(prefix + "address: required, unless the entry is identified by its RadSec"
                        + " or DTLS certificate (" + prefix + "radsec = true and " + prefix + "radsec.identity, or "
                        + prefix + "dtls = true and " + prefix + "dtls.identity)");
            }
            int slash = address.indexOf('/');
            String host = slash < 0 ? address : address.substring(0, slash);
            boolean v6 = !byCertificate && host.indexOf(':') >= 0;
            int prefixLength = byCertificate
                    ? -1
                    : slash < 0 ? (v6 ? 128 : 32) : parsePrefix(prefix, address.substring(slash + 1), v6 ? 128 : 32);
            int network = byCertificate || v6 ? 0 : ipv4(prefix + "address", host);
            byte[] network6 = v6 ? ipv6(prefix + "address", host) : null;
            byte[] secret = (byCertificate ? config.string(prefix + "secret", "") : config.string(prefix + "secret"))
                    .getBytes(StandardCharsets.UTF_8);
            NasClient.MessageAuthenticatorPolicy policy = config.enumValue(
                    prefix + "message-authenticator",
                    NasClient.MessageAuthenticatorPolicy.class,
                    NasClient.MessageAuthenticatorPolicy.OPTIONAL);
            int id = config.integer(prefix + "id", fnv1a(name));
            NasClient.Identity[] identity = identity(prefix, config.string(prefix + "identity", "source-ip"));
            if (prefixLength == 0 && identity.length == 0) {
                throw new ConfigException(prefix + "address: " + address + " accepts every source address, so the"
                        + " devices behind it must be told apart: set " + prefix + "identity (e.g. nas-identifier,"
                        + " called-station-id)");
            }
            clients.add(new NasClient(
                    name,
                    id,
                    network,
                    prefixLength,
                    secret,
                    config.string(prefix + "vendor", "default").toLowerCase(Locale.ROOT),
                    policy,
                    identity,
                    idleMinutes(prefix, config),
                    config.enumValue(
                            prefix + "access.message-authenticator",
                            NasClient.MessageAuthenticatorPolicy.class,
                            NasClient.MessageAuthenticatorPolicy.REQUIRED),
                    network6));
        }
        return new NasRegistry(clients);
    }

    /**
     * The NAS for a source address, or {@code null}. Allocation-free for IPv4, and for IPv6 while the same sender keeps
     * sending; IPv6 entries match longest prefix first.
     */
    public NasClient lookup(InetAddress address) {
        Table t = table;
        if (address instanceof Inet6Address v6) {
            if (v6 == t.lastAddress6) {
                return t.lastClient6;
            }
            byte[] bytes = v6.getAddress();
            NasClient found = null;
            for (NasClient c : t.ranges6) {
                if (c.matches6(bytes)) {
                    found = c;
                    break;
                }
            }
            t.lastClient6 = found;
            t.lastAddress6 = v6;
            return found;
        }
        if (!(address instanceof Inet4Address)) {
            return null;
        }
        int ip = address.hashCode();
        NasClient client = t.exact.get(ip);
        if (client != null) {
            return client;
        }
        for (NasClient range : t.ranges) {
            if (range.matches(ip)) {
                return range;
            }
        }
        DynamicClients d = dynamic;
        return d == null ? null : d.find(ip, System.currentTimeMillis());
    }

    /** Entries looked up on demand for addresses no configured entry covers ({@code nas.dynamic.*}). */
    void dynamic(DynamicClients clients) {
        this.dynamic = clients;
    }

    DynamicClients dynamic() {
        return dynamic;
    }

    static InetAddress inet(int address) {
        try {
            return InetAddress.getByAddress(
                    new byte[] {(byte) (address >>> 24), (byte) (address >>> 16), (byte) (address >>> 8), (byte) address
                    });
        } catch (java.net.UnknownHostException e) {
            throw new IllegalStateException(e); // four bytes are always an address
        }
    }

    public Collection<NasClient> clients() {
        return Collections.unmodifiableCollection(table.all);
    }

    static int fnv1a(String name) {
        int h = 0x811c9dc5;
        for (byte b : name.getBytes(StandardCharsets.UTF_8)) {
            h ^= b & 0xFF;
            h *= 0x01000193;
        }
        return h;
    }

    /** {@code nas.<name>.idle.timeout} in whole minutes, 1 to 65535; 0 when not set (the cluster default). */
    static int idleMinutes(String prefix, Config config) {
        if (!config.has(prefix + "idle.timeout")) {
            return 0;
        }
        java.time.Duration d = config.duration(prefix + "idle.timeout", java.time.Duration.ZERO);
        if (d.toSeconds() % 60 != 0 || d.toMinutes() < 1 || d.toMinutes() > 65_535) {
            throw new ConfigException(prefix + "idle.timeout: whole minutes from 1m to 65535m (about 3 interim"
                    + " intervals), got " + d);
        }
        return (int) d.toMinutes();
    }

    /** {@code source-ip} (empty) or a list of distinct device attributes, first present wins. */
    static NasClient.Identity[] identity(String prefix, String text) {
        List<NasClient.Identity> list = new ArrayList<>();
        String[] parts = text.split(",");
        for (String part : parts) {
            String v = part.trim().toLowerCase(Locale.ROOT);
            if (v.equals("source-ip")) {
                if (parts.length > 1) {
                    throw new ConfigException(prefix + "identity: source-ip cannot be combined with attributes");
                }
                return new NasClient.Identity[0];
            }
            NasClient.Identity match = null;
            for (NasClient.Identity i : NasClient.Identity.values()) {
                if (i.configName().equals(v)) {
                    match = i;
                }
            }
            if (match == null) {
                throw new ConfigException(prefix + "identity: unknown value \"" + v
                        + "\"; expected source-ip or a list of nas-identifier, called-station-id, nas-ip-address");
            }
            if (list.contains(match)) {
                throw new ConfigException(prefix + "identity: " + v + " listed twice");
            }
            list.add(match);
        }
        return list.toArray(NasClient.Identity[]::new);
    }

    private static int parsePrefix(String key, String text, int max) {
        try {
            int p = Integer.parseInt(text);
            if (p < 0 || p > max) {
                throw new NumberFormatException();
            }
            return p;
        } catch (NumberFormatException e) {
            throw new ConfigException(key + "address: invalid prefix length /" + text);
        }
    }

    /** An IPv6 literal (no host names), 16 bytes. */
    static byte[] ipv6(String key, String text) {
        if (!text.matches("[0-9A-Fa-f:.]+") || text.indexOf(':') < 0) {
            throw new ConfigException(key + ": expected an IPv6 address or CIDR range, got \"" + text + "\"");
        }
        try {
            byte[] b = InetAddress.getByName(text).getAddress();
            if (b.length != 16) {
                throw new ConfigException(key + ": " + text + " is not an IPv6 address");
            }
            return b;
        } catch (UnknownHostException e) {
            throw new ConfigException(key + ": invalid address " + text, e);
        }
    }

    static int ipv4(String key, String text) {
        if (!text.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            throw new ConfigException(key + ": expected an IPv4 address or CIDR range, got \"" + text + "\"");
        }
        try {
            return InetAddress.getByName(text).hashCode();
        } catch (UnknownHostException e) {
            throw new ConfigException(key + ": invalid address " + text, e);
        }
    }
}
