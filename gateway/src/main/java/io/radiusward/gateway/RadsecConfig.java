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
 * the NAS entries that may use it.
 *
 * @param enabled {@code radsec.enabled}
 * @param host the listen address ({@code gateway.listen.host})
 * @param port {@code radsec.port}, 2083 (0 = any free port, for tests)
 * @param credentials the server's certificate and key, the CAs of client certificates, revocation, reload
 * @param versions enabled TLS versions ({@code radsec.versions})
 * @param connections connections held at once ({@code radsec.connections}); more are closed right after accepting
 * @param handshakeTimeout a connection that has not completed its handshake by then is closed
 * @param idleTimeout a connection without traffic for this long is closed; zero = never
 * @param clients the NAS entries allowed over RadSec, by name
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
        Map<String, Client> clients) {

    /** RFC 6614 §2.3: the shared secret over TLS is {@code radsec} unless both sides agree on another. */
    static final String DEFAULT_SECRET = "radsec";

    public static final RadsecConfig DISABLED =
            new RadsecConfig(false, "0.0.0.0", 2083, null, List.of(), 0, Duration.ZERO, Duration.ZERO, Map.of());

    /**
     * A NAS entry's RadSec settings.
     *
     * @param secret {@code nas.<name>.radsec.secret}, default {@code radsec}
     * @param identity a name its client certificate must carry ({@code nas.<name>.radsec.identity}, the common name
     *     or a DNS, e-mail or UPN alternative name); {@code null}: any certificate of {@code radsec.ca}
     */
    public record Client(byte[] secret, String identity) {}

    public static RadsecConfig from(Config config, String listenHost) {
        if (!config.bool("radsec.enabled", false)) {
            return DISABLED;
        }
        String certificate = config.string("radsec.certificate");
        String ca = config.string("radsec.ca", "");
        if (ca.isBlank()) {
            throw new ConfigException("radsec.ca: required, RadSec clients authenticate with certificates (RFC 6614)");
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
        Map<String, Client> clients = new TreeMap<>();
        for (String name : config.names("nas")) {
            String prefix = "nas." + name + ".radsec";
            if (config.bool(prefix, false)) {
                String identity = config.string(prefix + ".identity", "").trim();
                clients.put(
                        name,
                        new Client(
                                config.string(prefix + ".secret", DEFAULT_SECRET)
                                        .getBytes(java.nio.charset.StandardCharsets.UTF_8),
                                identity.isEmpty() ? null : identity));
            }
        }
        if (clients.isEmpty()) {
            throw new ConfigException("radsec.enabled: no NAS entry allows it; set nas.<name>.radsec = true");
        }
        return new RadsecConfig(
                true,
                listenHost,
                config.integer("radsec.port", 2083),
                TlsCredentials.from(config, "radsec.", Path.of(certificate), Path.of(config.string("radsec.key")), ca),
                List.copyOf(versions),
                connections,
                config.duration("radsec.handshake.timeout", Duration.ofSeconds(10)),
                config.duration("radsec.idle.timeout", Duration.ZERO),
                Map.copyOf(clients));
    }
}
