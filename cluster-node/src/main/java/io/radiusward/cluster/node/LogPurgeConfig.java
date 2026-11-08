/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;

/**
 * Log purge settings (ADR 0014): {@code log.purge.enabled}, {@code log.purge.dry.run},
 * {@code archive.segment.length} (the purge granularity; a power of two, at least the term length),
 * {@code log.purge.interval} (how often members report their log position and purge).
 */
public record LogPurgeConfig(boolean enabled, boolean dryRun, int segmentLength, java.time.Duration interval) {

    public static final LogPurgeConfig DEFAULTS =
            new LogPurgeConfig(true, false, 128 << 20, java.time.Duration.ofMinutes(1));

    public static LogPurgeConfig from(Config config) {
        long segment = config.bytes("archive.segment.length", 128L << 20);
        if (segment > Integer.MAX_VALUE || Long.bitCount(segment) != 1) {
            throw new ConfigException("archive.segment.length: expected a power of two up to 1g, got " + segment);
        }
        return new LogPurgeConfig(
                config.bool("log.purge.enabled", true),
                config.bool("log.purge.dry.run", false),
                (int) segment,
                config.duration("log.purge.interval", java.time.Duration.ofMinutes(1)));
    }
}
