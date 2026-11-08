/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

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

    public StorageMode mode() {
        return StorageMode.parse(setting("mode", "sessions"));
    }
}
