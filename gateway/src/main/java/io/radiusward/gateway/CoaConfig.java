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
import java.time.Duration;
import java.util.Map;
import java.util.TreeMap;

/**
 * CoA and Disconnect-Request (RFC 5176, ADR 0036): {@code coa.*} for the gateway, {@code nas.<name>.coa.*} per NAS
 * entry.
 *
 * @param enabled {@code coa.enabled}
 * @param timeout how long to wait for an ACK or NAK before sending again ({@code coa.timeout})
 * @param retries how many times a request is sent again ({@code coa.retries})
 * @param token the bearer token of the HTTP API ({@code coa.api.token}); {@code null}: no HTTP API
 * @param targets per NAS entry name: where its dynamic-authorization server listens
 */
public record CoaConfig(boolean enabled, Duration timeout, int retries, String token, Map<String, Target> targets) {

    public static final int DEFAULT_PORT = 3799;

    public static final CoaConfig DISABLED = new CoaConfig(false, Duration.ofSeconds(2), 2, null, Map.of());

    /**
     * @param address {@code nas.<name>.coa.address}, {@code null}: the entry's address (a single address), or the
     *     session's NAS-IP-Address
     * @param port {@code nas.<name>.coa.port}
     * @param secret {@code nas.<name>.coa.secret}, {@code null}: the entry's secret
     */
    public record Target(InetAddress address, int port, byte[] secret) {}

    public static CoaConfig from(Config config) {
        if (!config.bool("coa.enabled", false)) {
            return DISABLED;
        }
        Duration timeout = config.duration("coa.timeout", Duration.ofSeconds(2));
        int retries = config.integer("coa.retries", 2);
        if (retries < 0 || retries > 10) {
            throw new ConfigException("coa.retries: 0 to 10, got " + retries);
        }
        String token = config.string("coa.api.token", "").trim();
        if (!token.isEmpty() && token.length() < 16) {
            throw new ConfigException("coa.api.token: at least 16 characters (it allows disconnecting any user)");
        }
        Map<String, Target> targets = new TreeMap<>();
        for (String name : config.names("nas")) {
            String prefix = "nas." + name + ".coa.";
            String address = config.string(prefix + "address", "").trim();
            String secret = config.string(prefix + "secret", "");
            try {
                targets.put(
                        name,
                        new Target(
                                address.isEmpty() ? null : InetAddress.getByName(address),
                                config.integer(prefix + "port", DEFAULT_PORT),
                                secret.isEmpty() ? null : secret.getBytes(StandardCharsets.UTF_8)));
            } catch (UnknownHostException e) {
                throw new ConfigException(prefix + "address: unknown host " + address, e);
            }
        }
        return new CoaConfig(true, timeout, retries, token.isEmpty() ? null : token, Map.copyOf(targets));
    }

    Target target(String nas) {
        Target t = targets.get(nas);
        return t != null ? t : new Target(null, DEFAULT_PORT, null);
    }
}
