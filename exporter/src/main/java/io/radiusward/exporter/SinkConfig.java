/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * One configured sink ({@code export.sinks = pg, archive} and {@code sink.<name>.*}, docs/configuration.md).
 *
 * @param settings every {@code sink.<name>.*} key without the prefix, handed to the plug-in
 */
public record SinkConfig(
        String name,
        String type,
        boolean required,
        long maxLagBytes,
        long maxLagMs,
        boolean detachOnMaxLag,
        int batchRows,
        long batchLingerMs,
        long leaseTimeoutMs,
        Map<String, String> settings) {

    public static List<SinkConfig> from(Config config) {
        List<SinkConfig> sinks = new ArrayList<>();
        for (String name : config.list("export.sinks", List.of())) {
            if (name.isBlank()) {
                continue;
            }
            if (name.length() > 32 || !name.matches("[a-z0-9][a-z0-9_-]*")) {
                throw new ConfigException(
                        "export.sinks: sink name \"" + name + "\" must be at most 32 characters of a-z, 0-9, _ and -");
            }
            String p = "sink." + name + ".";
            if (!config.has(p + "type")) {
                throw new ConfigException(p + "type is required (postgres, file, ...)");
            }
            boolean required = config.bool(p + "required", true);
            String onMaxLag = config.string(p + "on.max.lag", required ? "block" : "detach")
                    .toLowerCase(Locale.ROOT);
            if (!onMaxLag.equals("block") && !onMaxLag.equals("detach")) {
                throw new ConfigException(p + "on.max.lag: expected block or detach, got \"" + onMaxLag + "\"");
            }
            if (onMaxLag.equals("block") && !required) {
                throw new ConfigException(p + "on.max.lag=block needs " + p + "required=true");
            }
            sinks.add(new SinkConfig(
                    name,
                    config.string(p + "type"),
                    required,
                    config.bytes(p + "max.lag.bytes", 0),
                    config.duration(p + "max.lag", Duration.ofHours(4)).toMillis(),
                    onMaxLag.equals("detach"),
                    config.integer(p + "batch.rows", 5000),
                    config.duration(p + "batch.linger", Duration.ofMillis(200)).toMillis(),
                    config.duration("export.lease.timeout", Duration.ofSeconds(10))
                            .toMillis(),
                    Map.copyOf(config.subset("sink." + name))));
        }
        return sinks;
    }
}
