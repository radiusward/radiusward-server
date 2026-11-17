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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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
        // the last IPv6 sender and its entry: the JDK hands out the same address object for a repeating sender.
        // One object, so threads looking up at once never see one sender's address with another's entry.
        volatile LastSender last6;
    }

    /** An IPv6 sender and the entry it matched ({@code null}: none). */
    private record LastSender(Inet6Address address, NasClient client) {}

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

    /** The configured entries alone, without {@code nas.dynamic.*} (a reload keeps the running lookups). */
    static NasRegistry configured(Config config) {
        return new NasRegistry(NasConfig.entries(config));
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

    /**
     * The NAS for a source address, or {@code null}. Allocation-free for IPv4, and for IPv6 while the same sender keeps
     * sending; IPv6 entries match longest prefix first.
     */
    public NasClient lookup(InetAddress address) {
        Table t = table;
        if (address instanceof Inet6Address v6) {
            LastSender last = t.last6;
            if (last != null && last.address() == v6) {
                return last.client();
            }
            byte[] bytes = v6.getAddress();
            NasClient found = null;
            for (NasClient c : t.ranges6) {
                if (c.matches6(bytes)) {
                    found = c;
                    break;
                }
            }
            t.last6 = new LastSender(v6, found); // a miss allocates already (getAddress)
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
}
