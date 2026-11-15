/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import io.radiusward.units.Units;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * What a sink gets from the exporter.
 *
 * @param name the configured sink name ({@code sink.<name>.*})
 * @param memberId the cluster member running this exporter
 * @param settings every {@code sink.<name>.*} key without the prefix, e.g. {@code url}, {@code mode}
 * @param attributes decodes {@code rawAttributes} with the dictionaries in use
 */
public record SinkContext(String name, int memberId, Map<String, String> settings, Attributes attributes) {

    public String setting(String key, String fallback) {
        return settings.getOrDefault(key, fallback);
    }

    public String required(String key) {
        String value = settings.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("sink." + name + "." + key + " is required");
        }
        return value;
    }

    /**
     * A duration such as {@code 500ms}, {@code 3s}, {@code 5m}, {@code 12h}, {@code 90d}.
     *
     * @param bare the unit of a number without one, {@code null} if a unit is required (except for {@code 0})
     */
    public Duration duration(String key, String fallback, ChronoUnit bare) {
        String text = setting(key, fallback);
        try {
            return Units.duration(text, bare);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("sink." + name + "." + key + ": " + e.getMessage());
        }
    }

    /** A size such as {@code 512}, {@code 64k}, {@code 256m}, {@code 1g}. */
    public long bytes(String key, String fallback) {
        String text = setting(key, fallback);
        try {
            return Units.bytes(text);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("sink." + name + "." + key + ": " + e.getMessage());
        }
    }

    public StorageMode mode() {
        return StorageMode.parse(setting("mode", "sessions"));
    }
}
