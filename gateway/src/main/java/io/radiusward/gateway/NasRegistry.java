/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.net.Inet4Address;
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
 * </pre>
 */
public final class NasRegistry {

    private final Int2ObjectHashMap<NasClient> exact = new Int2ObjectHashMap<>();
    private final NasClient[] ranges;
    private final List<NasClient> all;

    private NasRegistry(List<NasClient> clients) {
        List<NasClient> rangeList = new ArrayList<>();
        Map<Integer, String> ids = new HashMap<>();
        for (NasClient c : clients) {
            String other = ids.put(c.id(), c.name());
            if (other != null) {
                throw new ConfigException("nas." + c.name() + ".id: id " + c.id() + " already used by nas." + other
                        + "; set nas.<name>.id explicitly");
            }
            if (c.prefixLength() == 32) {
                if (exact.put(c.network(), c) != null) {
                    throw new ConfigException("nas." + c.name() + ".address: duplicate address");
                }
            } else {
                rangeList.add(c);
            }
        }
        this.ranges = rangeList.toArray(NasClient[]::new);
        this.all = List.copyOf(clients);
    }

    public static NasRegistry of(List<NasClient> clients) {
        return new NasRegistry(clients);
    }

    public static NasRegistry from(Config config) {
        List<NasClient> clients = new ArrayList<>();
        for (String name : config.names("nas")) {
            String prefix = "nas." + name + ".";
            String address = config.string(prefix + "address");
            int slash = address.indexOf('/');
            int prefixLength = slash < 0 ? 32 : parsePrefix(prefix, address.substring(slash + 1));
            int network = ipv4(prefix + "address", slash < 0 ? address : address.substring(0, slash));
            byte[] secret = config.string(prefix + "secret").getBytes(StandardCharsets.UTF_8);
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
                    identity));
        }
        if (clients.isEmpty()) {
            throw new ConfigException("no NAS configured: add nas.<name>.address and nas.<name>.secret");
        }
        return new NasRegistry(clients);
    }

    /** The NAS for a source address, or {@code null}. Allocation-free for IPv4. */
    public NasClient lookup(InetAddress address) {
        if (!(address instanceof Inet4Address)) {
            return null; // IPv6 NAS support arrives later
        }
        int ip = address.hashCode();
        NasClient client = exact.get(ip);
        if (client != null) {
            return client;
        }
        for (NasClient range : ranges) {
            if (range.matches(ip)) {
                return range;
            }
        }
        return null;
    }

    public Collection<NasClient> clients() {
        return Collections.unmodifiableCollection(all);
    }

    static int fnv1a(String name) {
        int h = 0x811c9dc5;
        for (byte b : name.getBytes(StandardCharsets.UTF_8)) {
            h ^= b & 0xFF;
            h *= 0x01000193;
        }
        return h;
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

    private static int parsePrefix(String key, String text) {
        try {
            int p = Integer.parseInt(text);
            if (p < 0 || p > 32) {
                throw new NumberFormatException();
            }
            return p;
        } catch (NumberFormatException e) {
            throw new ConfigException(key + "address: invalid prefix length /" + text);
        }
    }

    private static int ipv4(String key, String text) {
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
