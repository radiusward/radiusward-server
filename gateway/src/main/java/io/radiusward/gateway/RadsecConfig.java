/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * RadSec, RADIUS over TLS (RFC 6614, ADR 0034): {@code radsec.*} for the listener and {@code nas.<name>.radsec*} for
 * the NAS entries that may use it; RADIUS over DTLS (RFC 7360, ADR 0038) with the same certificates:
 * {@code radsec.dtls.*} and {@code nas.<name>.dtls*}.
 *
 * @param enabled whether the RadSec agent runs: over TCP ({@code radsec.enabled}), DTLS, or both
 * @param host the listen address ({@code gateway.listen.host})
 * @param port {@code radsec.port}, 2083 (0 = any free port, for tests)
 * @param credentials the server's certificate and key, the CAs of client certificates, revocation, reload
 * @param versions enabled TLS versions ({@code radsec.versions})
 * @param connections connections held at once ({@code radsec.connections}); more are closed right after accepting
 * @param handshakeTimeout a connection that has not completed its handshake by then is closed
 * @param idleTimeout a connection without traffic for this long is closed; zero = never
 * @param clients the NAS entries allowed over RadSec, by name
 * @param tcp whether the TCP listener runs ({@code radsec.enabled})
 * @param dtls the DTLS listener
 */
public record RadsecConfig(
        boolean enabled,
        String host,
        int port,
        TlsCredentials credentials,
        List<String> versions,
        int connections,
        Duration handshakeTimeout,
        Duration idleTimeout,
        Map<String, Client> clients,
        boolean tcp,
        Dtls dtls) {

    /** RFC 6614 §2.3: the shared secret over TLS is {@code radsec} unless both sides agree on another. */
    static final String DEFAULT_SECRET = "radsec";

    /** RFC 7360 §2.1: the shared secret over DTLS is {@code radius/dtls}. */
    static final String DEFAULT_DTLS_SECRET = "radius/dtls";

    public static final RadsecConfig DISABLED = new RadsecConfig(
            false, "0.0.0.0", 2083, null, List.of(), 0, Duration.ZERO, Duration.ZERO, Map.of(), false, Dtls.DISABLED);

    /**
     * RADIUS over DTLS 1.2 (RFC 7360): one association per NAS address and port on a UDP socket.
     *
     * @param enabled {@code radsec.dtls.enabled}
     * @param port {@code radsec.dtls.port}, 2083 (0 = any free port, for tests)
     * @param associations associations held at once ({@code radsec.dtls.associations}); a ClientHello beyond is dropped
     * @param idleTimeout an association without traffic for this long is closed ({@code radsec.dtls.idle.timeout})
     * @param retransmit the first handshake retransmission interval, doubled up to 8 times as long (RFC 6347 §4.2.4)
     * @param clients the NAS entries allowed over DTLS, by name ({@code nas.<name>.dtls})
     */
    public record Dtls(
            boolean enabled,
            int port,
            int associations,
            Duration idleTimeout,
            Duration retransmit,
            Map<String, Client> clients) {

        static final Dtls DISABLED = new Dtls(false, 2083, 0, Duration.ZERO, Duration.ofSeconds(1), Map.of());
    }

    /**
     * A NAS entry's RadSec settings.
     *
     * @param secret {@code nas.<name>.radsec.secret}, default {@code radsec}
     * @param identity a name its client certificate must carry ({@code nas.<name>.radsec.identity}, the common name
     *     or a DNS, e-mail or UPN alternative name); {@code null}: any certificate of {@code radsec.ca}
     */
    public record Client(byte[] secret, String identity) {}

    public static RadsecConfig from(Config config, String listenHost) {
        boolean tcp = config.bool("radsec.enabled", false);
        boolean udp = config.bool("radsec.dtls.enabled", false);
        if (!tcp && !udp) {
            return DISABLED;
        }
        String what = tcp ? "radsec.enabled" : "radsec.dtls.enabled";
        String certificate = config.string("radsec.certificate");
        String ca = config.string("radsec.ca", "");
        if (ca.isBlank()) {
            throw new ConfigException(
                    "radsec.ca: required, RadSec and DTLS clients authenticate with certificates (RFC 6614, RFC 7360)");
        }
        List<String> versions = config.list("radsec.versions", List.of("TLSv1.2", "TLSv1.3"));
        for (String v : versions) {
            if (!v.equals("TLSv1.2") && !v.equals("TLSv1.3")) {
                throw new ConfigException("radsec.versions: TLSv1.2 and/or TLSv1.3, got " + v);
            }
        }
        int connections = config.integer("radsec.connections", 256);
        if (connections < 1) {
            throw new ConfigException("radsec.connections: at least 1");
        }
        Map<String, Client> clients = tcp ? clients(config, "radsec", DEFAULT_SECRET) : Map.of();
        if (tcp && clients.isEmpty()) {
            throw new ConfigException("radsec.enabled: no NAS entry allows it; set nas.<name>.radsec = true");
        }
        Dtls dtls = Dtls.DISABLED;
        if (udp) {
            Map<String, Client> dtlsClients = clients(config, "dtls", DEFAULT_DTLS_SECRET);
            if (dtlsClients.isEmpty()) {
                throw new ConfigException("radsec.dtls.enabled: no NAS entry allows it; set nas.<name>.dtls = true");
            }
            int associations = config.integer("radsec.dtls.associations", 256);
            if (associations < 1) {
                throw new ConfigException("radsec.dtls.associations: at least 1");
            }
            Duration retransmit = config.duration("radsec.dtls.retransmit", Duration.ofSeconds(1));
            if (retransmit.isZero() || retransmit.isNegative()) {
                throw new ConfigException("radsec.dtls.retransmit: more than zero");
            }
            dtls = new Dtls(
                    true,
                    config.integer("radsec.dtls.port", 2083),
                    associations,
                    config.duration("radsec.dtls.idle.timeout", Duration.ofMinutes(15)),
                    retransmit,
                    dtlsClients);
        }
        return new RadsecConfig(
                true,
                listenHost,
                config.integer("radsec.port", 2083),
                TlsCredentials.from(
                        config,
                        "radsec.",
                        Path.of(certificate),
                        Path.of(config.string("radsec.key")),
                        ca,
                        config.duration("radsec.session.timeout", Duration.ofHours(1))),
                List.copyOf(versions),
                connections,
                config.duration("radsec.handshake.timeout", Duration.ofSeconds(10)),
                config.duration("radsec.idle.timeout", Duration.ZERO),
                clients,
                tcp,
                dtls);
    }

    /** The NAS entries with {@code nas.<name>.<key> = true}, their {@code .secret} and {@code .identity}. */
    private static Map<String, Client> clients(Config config, String key, String defaultSecret) {
        Map<String, Client> clients = new TreeMap<>();
        for (String name : config.names("nas")) {
            String prefix = "nas." + name + "." + key;
            if (config.bool(prefix, false)) {
                String identity = config.string(prefix + ".identity", "").trim();
                clients.put(
                        name,
                        new Client(
                                config.string(prefix + ".secret", defaultSecret)
                                        .getBytes(java.nio.charset.StandardCharsets.UTF_8),
                                identity.isEmpty() ? null : identity));
            }
        }
        return Map.copyOf(clients);
    }
}
