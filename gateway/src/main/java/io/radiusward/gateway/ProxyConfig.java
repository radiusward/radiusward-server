/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Proxying (ADR 0037): {@code realm.<id>.*} sends the users of a realm to a pool of home servers instead of the
 * identity stores, {@code pool.<id>.*} and {@code home.<id>.*} describe them, {@code proxy.*} the timing. A user
 * without a configured realm is decided locally; a realm is either local or proxied, never both.
 *
 * <pre>
 * proxy.enabled = true
 * home.partner-a.address = 192.0.2.10        # port 1812 (2083 with transport = tls)
 * home.partner-a.secret  = ${env:PARTNER_SECRET}
 * pool.partner.servers   = partner-a, partner-b
 * pool.partner.type      = failover          # or load-balance (per device, so an EAP conversation stays put)
 * realm.partner.name     = partner.example   # user@partner.example and PARTNER.EXAMPLE&#92;user
 * realm.partner.pool     = partner
 * realm.partner.strip    = false
 * </pre>
 *
 * @param enabled {@code proxy.enabled}
 * @param timeout how long to wait for a home server's answer before sending again ({@code proxy.timeout})
 * @param retries how many times a request is sent again to the same home server ({@code proxy.retries})
 * @param deadAfter a home server that answered nothing for this long while requests were sent is dead
 *     ({@code proxy.dead.after}); it gets no requests until it answers a Status-Server again
 * @param statusInterval how often Status-Server probes go to every home server ({@code proxy.status.interval})
 * @param pending proxied Access-Requests in flight at once ({@code proxy.pending})
 * @param requireMessageAuthenticator answers without a Message-Authenticator are ignored
 *     ({@code proxy.require.message-authenticator}, BlastRADIUS)
 * @param coaPort where CoA and Disconnect-Requests from home servers with {@code home.<id>.coa = true} are received
 *     and relayed to the NAS ({@code proxy.coa.port}, 3799; ADR 0043); no listener without such a home server
 * @param inner whether a tunnel (PEAP, TTLS, TEAP) for an inner user of a proxied realm ends here and only the inner
 *     credential goes to the realm's home servers ({@code proxy.inner}, ADR 0044)
 */
public record ProxyConfig(
        boolean enabled,
        Duration timeout,
        int retries,
        Duration deadAfter,
        Duration statusInterval,
        int pending,
        List<Realm> realms,
        Map<String, Pool> pools,
        Map<String, Home> homes,
        Discovery discovery,
        boolean requireMessageAuthenticator,
        int coaPort,
        boolean inner) {

    public static final ProxyConfig DISABLED = new ProxyConfig(
            false,
            Duration.ofSeconds(3),
            2,
            Duration.ofSeconds(30),
            Duration.ofSeconds(10),
            1024,
            List.of(),
            Map.of(),
            Map.of(),
            Discovery.OFF,
            true,
            3799,
            false);

    /**
     * @param name the realm in lower case, {@code *} for every realm no other entry names
     * @param pool the pool its users go to; {@code null} with {@code discover}
     * @param strip whether the home server gets the user name without the realm
     * @param discover find the home servers in DNS (RFC 7585) instead of a pool ({@code realm.<id>.discover})
     */
    public record Realm(String name, byte[] nameBytes, String pool, boolean strip, boolean discover) {}

    /** @param loadBalance {@code pool.<id>.type = load-balance}: spread by device, else the first one alive */
    public record Pool(String name, List<String> servers, boolean loadBalance) {}

    /**
     * A home server.
     *
     * @param tls {@code home.<id>.transport = tls} (RadSec, RFC 6614); the secret defaults to {@code radsec}
     * @param certificate our client certificate and key (PEM) for TLS
     * @param ca the CAs the home server's certificate must chain to
     * @param serverName a name the home server's certificate must carry; {@code null}: the configured host name
     * @param coa whether it may send CoA and Disconnect-Requests for its users to us ({@code home.<id>.coa}, UDP)
     */
    public record Home(
            String name,
            InetAddress address,
            String host,
            int port,
            byte[] secret,
            boolean tls,
            Path certificate,
            Path key,
            Path ca,
            String serverName,
            boolean coa) {

        /** Whether it is relayed CoA: a UDP home server allowed to send it. */
        boolean relaysCoa() {
            return coa && !tls;
        }
    }

    /** Whether CoA from home servers is relayed: a home server allows it. */
    boolean coaRelay() {
        return enabled && homes.values().stream().anyMatch(Home::relaysCoa);
    }

    /**
     * RFC 7585 dynamic discovery ({@code proxy.discovery.*}), for realms with {@code discover = true}: TLS home servers
     * from NAPTR and SRV records.
     *
     * @param dnsServer a DNS server to ask instead of the system's ({@code proxy.discovery.dns.server}, tests)
     * @param ttl how long a lookup is kept; a failed one for {@code negativeTtl}
     */
    public record Discovery(
            String dnsServer, Duration ttl, Duration negativeTtl, Path certificate, Path key, Path ca, byte[] secret) {
        public static final Discovery OFF =
                new Discovery(null, Duration.ofHours(1), Duration.ofMinutes(5), null, null, null, null);
    }

    public static ProxyConfig from(Config config) {
        if (!config.bool("proxy.enabled", false)) {
            return DISABLED;
        }
        Map<String, Home> homes = new TreeMap<>();
        for (String id : config.names("home")) {
            homes.put(id, home(config, id));
        }
        Map<String, Pool> pools = new TreeMap<>();
        for (String id : config.names("pool")) {
            String prefix = "pool." + id + ".";
            List<String> servers = config.list(prefix + "servers").stream()
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList();
            if (servers.isEmpty()) {
                throw new ConfigException(prefix + "servers: at least one home server");
            }
            for (String s : servers) {
                if (!homes.containsKey(s)) {
                    throw new ConfigException(prefix + "servers: no home." + s + ".*");
                }
            }
            String type = config.string(prefix + "type", "failover").trim();
            if (!type.equals("failover") && !type.equals("load-balance")) {
                throw new ConfigException(prefix + "type: failover or load-balance, got " + type);
            }
            pools.put(id, new Pool(id, servers, type.equals("load-balance")));
        }
        List<Realm> realms = new ArrayList<>();
        boolean anyDiscovery = false;
        for (String id : config.names("realm")) {
            String prefix = "realm." + id + ".";
            String name = config.string(prefix + "name", id).trim().toLowerCase(Locale.ROOT);
            boolean discover = config.bool(prefix + "discover", false);
            String pool = config.string(prefix + "pool", "").trim();
            if (!discover && !pools.containsKey(pool)) {
                throw new ConfigException(prefix + "pool: no pool." + pool + ".* (or set " + prefix + "discover)");
            }
            if (discover && name.equals("*")) {
                throw new ConfigException(prefix + "discover: needs a realm name, not *");
            }
            anyDiscovery |= discover;
            realms.add(new Realm(
                    name,
                    name.getBytes(StandardCharsets.UTF_8),
                    discover ? null : pool,
                    config.bool(prefix + "strip", false),
                    discover));
        }
        if (realms.isEmpty()) {
            throw new ConfigException("proxy.enabled: no realm.<id>.name to proxy");
        }
        realms.sort((a, b) ->
                a.name().equals("*") ? 1 : b.name().equals("*") ? -1 : a.name().compareTo(b.name()));
        int pending = config.integer("proxy.pending", 1024);
        if (pending < 1) {
            throw new ConfigException("proxy.pending: at least 1");
        }
        return new ProxyConfig(
                true,
                config.duration("proxy.timeout", Duration.ofSeconds(3)),
                config.integer("proxy.retries", 2),
                config.duration("proxy.dead.after", Duration.ofSeconds(30)),
                config.duration("proxy.status.interval", Duration.ofSeconds(10)),
                pending,
                List.copyOf(realms),
                Map.copyOf(pools),
                Map.copyOf(homes),
                anyDiscovery ? discovery(config) : Discovery.OFF,
                config.bool("proxy.require.message-authenticator", true),
                config.integer("proxy.coa.port", 3799),
                config.bool("proxy.inner", false));
    }

    private static Home home(Config config, String id) {
        String prefix = "home." + id + ".";
        boolean tls = switch (config.string(prefix + "transport", "udp").trim()) {
            case "udp" -> false;
            case "tls" -> true;
            default -> throw new ConfigException(prefix + "transport: udp or tls");
        };
        String address = config.string(prefix + "address").trim();
        int colon = address.lastIndexOf(':');
        String host = colon > 0 && address.indexOf(':') == colon ? address.substring(0, colon) : address;
        int port = colon > 0 && address.indexOf(':') == colon
                ? Integer.parseInt(address.substring(colon + 1))
                : config.integer(prefix + "port", tls ? 2083 : 1812);
        String secret = config.string(prefix + "secret", tls ? RadsecConfig.DEFAULT_SECRET : "");
        if (secret.isEmpty()) {
            throw new ConfigException(prefix + "secret: required over UDP");
        }
        InetAddress resolved;
        try {
            resolved = InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            throw new ConfigException(prefix + "address: unknown host " + host, e);
        }
        if (tls && config.string(prefix + "tls.ca", "").isBlank()) {
            throw new ConfigException(prefix + "tls.ca: required, the home server's certificate must be checked");
        }
        String name = config.string(prefix + "tls.name", "").trim();
        return new Home(
                id,
                resolved,
                host,
                port,
                secret.getBytes(StandardCharsets.UTF_8),
                tls,
                path(config, prefix + "tls.certificate"),
                path(config, prefix + "tls.key"),
                path(config, prefix + "tls.ca"),
                name.isEmpty() ? null : name,
                coa(config, prefix, tls));
    }

    private static boolean coa(Config config, String prefix, boolean tls) {
        boolean coa = config.bool(prefix + "coa", false);
        if (coa && tls) {
            throw new ConfigException(prefix + "coa: CoA from home servers is relayed over UDP only");
        }
        return coa;
    }

    private static Discovery discovery(Config config) {
        String ca = config.string("proxy.discovery.tls.ca", "");
        if (ca.isBlank()) {
            throw new ConfigException("proxy.discovery.tls.ca: required, discovered servers must be checked");
        }
        String dns = config.string("proxy.discovery.dns.server", "").trim();
        return new Discovery(
                dns.isEmpty() ? null : dns,
                config.duration("proxy.discovery.ttl", Duration.ofHours(1)),
                config.duration("proxy.discovery.negative.ttl", Duration.ofMinutes(5)),
                path(config, "proxy.discovery.tls.certificate"),
                path(config, "proxy.discovery.tls.key"),
                Path.of(ca),
                config.string("proxy.discovery.secret", RadsecConfig.DEFAULT_SECRET)
                        .getBytes(StandardCharsets.UTF_8));
    }

    private static Path path(Config config, String key) {
        String value = config.string(key, "").trim();
        return value.isEmpty() ? null : Path.of(value);
    }

    /**
     * The realm of a User-Name, matched without allocation: {@code user@realm} or {@code REALM}&#92;{@code user}, case-folded;
     * {@code *} for any other realm. {@code null}: no proxied realm, decided locally.
     */
    Realm realmOf(org.agrona.DirectBuffer name, int offset, int length) {
        int at = -1;
        int backslash = -1;
        for (int i = 0; i < length; i++) {
            byte b = name.getByte(offset + i);
            if (b == '@') {
                at = i;
            } else if (b == '\\' && backslash < 0) {
                backslash = i;
            }
        }
        int start;
        int end;
        if (at >= 0) {
            start = at + 1;
            end = length;
        } else if (backslash > 0) {
            start = 0;
            end = backslash;
        } else {
            return null;
        }
        Realm any = null;
        for (Realm r : realms) {
            if (r.name().equals("*")) {
                any = r;
            } else if (equalsIgnoreCase(name, offset + start, end - start, r.nameBytes())) {
                return r;
            }
        }
        return end > start ? any : null;
    }

    private static boolean equalsIgnoreCase(org.agrona.DirectBuffer name, int offset, int length, byte[] lower) {
        if (length != lower.length) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            int c = name.getByte(offset + i);
            if (c >= 'A' && c <= 'Z') {
                c += 'a' - 'A';
            }
            if (c != lower[i]) {
                return false;
            }
        }
        return true;
    }
}
