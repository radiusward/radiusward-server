/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * NAS entries from {@code nas.<name>.*}: address or CIDR range (IPv4 or IPv6), or none for an entry identified by its
 * RadSec or DTLS certificate; secret, id, vendor, Message-Authenticator policies, how devices behind a range are told
 * apart, idle timeout. Every mistake is a {@link ConfigException} naming its key.
 */
final class NasConfig {

    private NasConfig() {}

    /** The entries of {@code nas.<name>.*}, without {@code nas.dynamic.*}. */
    static List<NasClient> entries(Config config) {
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
        return clients;
    }

    /** An entry without an address, known by the {@code identity} of its {@code transport} certificate. */
    private static boolean byCertificate(Config config, String prefix, String transport) {
        return config.bool(prefix + transport, false)
                && !config.string(prefix + transport + ".identity", "").isBlank();
    }

    /** The default id of an entry: FNV-1a of its name, the same on every RADIUS server. */
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
