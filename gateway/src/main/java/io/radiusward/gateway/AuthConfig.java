/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;

/**
 * Authentication on the gateway ({@code gateway.auth.*}, Phase 5): the Access-Request socket and its bounded
 * resources.
 *
 * @param enabled whether the gateway answers Access-Requests
 * @param port UDP port (1812); 0 picks a free one (tests)
 * @param workers threads that decide requests (identity store look-ups may block them, never the socket)
 * @param pending requests between the socket and the workers (power of two); beyond it requests are dropped
 * @param replyCacheEntries replies kept to answer retransmissions (RFC 5080); each up to
 *     {@link ReplyCache#MAX_REPLY} bytes
 * @param replyCacheTtl how long a reply is kept
 * @param reservationTimeout how long a worker waits for the cluster's answer to a simultaneous-use reservation;
 *     without one the request is not answered (ADR 0023)
 * @param reservationTtl how long a granted reservation waits for the device's Accounting-Start
 */
public record AuthConfig(
        boolean enabled,
        int port,
        int workers,
        int pending,
        int replyCacheEntries,
        Duration replyCacheTtl,
        Duration reservationTimeout,
        Duration reservationTtl) {

    public static final AuthConfig DISABLED = new AuthConfig(false, 1812, 4, 256, 4096, Duration.ofSeconds(10));

    public AuthConfig {
        if (workers < 1 || workers > 256) {
            throw new ConfigException("gateway.auth.workers: 1 to 256, got " + workers);
        }
        if (pending < 2 || Integer.bitCount(pending) != 1 || pending > 65_536) {
            throw new ConfigException("gateway.auth.pending: a power of two from 2 to 65536, got " + pending);
        }
        if (replyCacheEntries < 16 || replyCacheEntries > 1 << 20) {
            throw new ConfigException("gateway.auth.reply.cache.entries: 16 to 1048576, got " + replyCacheEntries);
        }
        if (replyCacheTtl.isNegative() || replyCacheTtl.isZero()) {
            throw new ConfigException("gateway.auth.reply.cache.ttl: must be positive");
        }
        if (port < 0 || port > 65_535) {
            throw new ConfigException("gateway.auth.port: 0 to 65535, got " + port);
        }
        if (reservationTimeout.isNegative() || reservationTimeout.isZero()) {
            throw new ConfigException("gateway.auth.reservation.timeout: must be positive");
        }
        if (reservationTtl.toSeconds() < 1 || reservationTtl.toSeconds() > 65_535) {
            throw new ConfigException("gateway.auth.reservation.ttl: 1s to 65535s, got " + reservationTtl);
        }
    }

    public AuthConfig(
            boolean enabled, int port, int workers, int pending, int replyCacheEntries, Duration replyCacheTtl) {
        this(
                enabled,
                port,
                workers,
                pending,
                replyCacheEntries,
                replyCacheTtl,
                Duration.ofSeconds(1),
                Duration.ofSeconds(60));
    }

    public static AuthConfig from(Config config) {
        return new AuthConfig(
                config.bool("gateway.auth.enabled", false),
                config.integer("gateway.auth.port", 1812),
                config.integer("gateway.auth.workers", 4),
                config.integer("gateway.auth.pending", 256),
                config.integer("gateway.auth.reply.cache.entries", 4096),
                config.duration("gateway.auth.reply.cache.ttl", Duration.ofSeconds(10)),
                config.duration("gateway.auth.reservation.timeout", Duration.ofSeconds(1)),
                config.duration("gateway.auth.reservation.ttl", Duration.ofSeconds(60)));
    }
}
