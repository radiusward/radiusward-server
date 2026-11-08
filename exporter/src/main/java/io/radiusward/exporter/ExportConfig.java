/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.common.config.Config;
import java.nio.file.Path;
import java.util.List;

/**
 * Export settings of a cluster member: {@code export.sinks}, {@code sink.<name>.*}, {@code export.plugins.dir},
 * {@code dictionary.dir}. No sinks: no exporter.
 */
public record ExportConfig(List<SinkConfig> sinks, Path pluginsDir, Path dictionaryDir) {

    public static final ExportConfig NONE = new ExportConfig(List.of(), null, null);

    public static ExportConfig from(Config config) {
        return new ExportConfig(
                SinkConfig.from(config),
                Path.of(config.string("export.plugins.dir", "/opt/radiusward/plugins")),
                Path.of(config.string("dictionary.dir", "/etc/radiusward/dictionary.d")));
    }

    public boolean enabled() {
        return !sinks.isEmpty();
    }
}
