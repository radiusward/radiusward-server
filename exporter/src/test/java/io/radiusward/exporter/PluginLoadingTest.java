/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.ConfigException;
import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.SinkContext;
import io.radiusward.export.SinkProvider;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PluginLoadingTest {

    /** A sink type registered only through a jar in the plug-ins directory. */
    public static final class TestProvider implements SinkProvider {
        @Override
        public String type() {
            return "test-plugin";
        }

        @Override
        public AccountingSink create() {
            return new AccountingSink() {
                @Override
                public void open(SinkContext context) {}

                @Override
                public CheckpointStyle checkpointStyle() {
                    return CheckpointStyle.IDEMPOTENT_REPLAY;
                }

                @Override
                public long storedPosition() {
                    return -1;
                }

                @Override
                public void write(Batch batch) {}

                @Override
                public void close() {}
            };
        }
    }

    @Test
    void providersComeFromTheClassPathAndThePluginsDirectory(@TempDir Path plugins) throws Exception {
        assertThat(Exporter.providers(null)).doesNotContainKey("test-plugin");
        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(plugins.resolve("test-sink.jar")))) {
            jar.putNextEntry(new JarEntry("META-INF/services/" + SinkProvider.class.getName()));
            jar.write((TestProvider.class.getName() + "\n").getBytes(StandardCharsets.UTF_8));
            jar.closeEntry();
        }
        Files.writeString(plugins.resolve("README.txt"), "not a jar");
        assertThat(Exporter.providers(plugins)).containsKey("test-plugin");
        assertThat(Exporter.providers(plugins.resolve("missing"))).doesNotContainKey("test-plugin");
    }

    @Test
    void aSinkTypeGivenInCodeMustNotAlsoBeAPluginsOrAnotherOnes() {
        SinkConfig sink = new SinkConfig("mine", "mine", true, 0, 0, false, 10, 10, 2000, Map.of());
        ExporterContext context = new ExporterContext(0, null, null, null, null, null, null, null, null);
        SinkProvider mine = SinkProvider.of("mine", () -> new TestProvider().create());
        assertThatThrownBy(() -> Exporter.start(List.of(sink), List.of(mine, mine), context))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("sink type mine given in code is also a plug-in's type");
        assertThat(Exporter.start(List.of(), List.of(mine), context).status())
                .as("no sinks configured: nothing is created")
                .isEmpty();
    }

    @Test
    void exportConfigCarriesTheProvidersGivenInCode() {
        SinkProvider mine = SinkProvider.of("mine", () -> new TestProvider().create());
        ExportConfig config = ExportConfig.NONE.withProviders(mine);
        assertThat(config.providers()).containsExactly(mine);
        assertThat(config.enabled()).isFalse();
        assertThat(ExportConfig.NONE.providers()).isEmpty();
    }
}
