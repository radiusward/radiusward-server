/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.common.config.Config;
import io.radiusward.export.SinkProvider;
import java.nio.file.Path;
import java.util.List;

/**
 * Export settings of a cluster member: {@code export.sinks}, {@code sink.<name>.*}, {@code export.plugins.dir},
 * {@code dictionary.dir}. No sinks: no exporter.
 *
 * @param providers sink providers given in code (an embedded member, a test) besides the plug-ins found on the class
 *     path and in {@code export.plugins.dir}; {@code sink.<name>.type} names their types as it names a plug-in's
 */
public record ExportConfig(List<SinkConfig> sinks, Path pluginsDir, Path dictionaryDir, List<SinkProvider> providers) {

    public static final ExportConfig NONE = new ExportConfig(List.of(), null, null);

    public ExportConfig {
        sinks = List.copyOf(sinks);
        providers = List.copyOf(providers);
    }

    /** Only plug-ins. */
    public ExportConfig(List<SinkConfig> sinks, Path pluginsDir, Path dictionaryDir) {
        this(sinks, pluginsDir, dictionaryDir, List.of());
    }

    /** The same settings with sink providers given in code. */
    public ExportConfig withProviders(SinkProvider... providers) {
        return new ExportConfig(sinks, pluginsDir, dictionaryDir, List.of(providers));
    }

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
