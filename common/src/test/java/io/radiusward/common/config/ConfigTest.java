/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.Profile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigTest {

    @Test
    void filesLoadInOrderAndEnvironmentWins(@TempDir Path dir) throws IOException {
        Path base = Files.writeString(dir.resolve("base.properties"), "a=1\nb=base\ncluster.node-id=0\n");
        Path local = Files.writeString(dir.resolve("local.properties"), "b=local\n");
        Config config = Config.load(List.of(base, local), Map.of("RADIUSWARD_CLUSTER_NODE_ID", "2"));
        assertThat(config.integer("a")).isEqualTo(1);
        assertThat(config.string("b")).isEqualTo("local");
        assertThat(config.integer("cluster.node-id")).isEqualTo(2);
        assertThat(Config.envName("cluster.node-id")).isEqualTo("RADIUSWARD_CLUSTER_NODE_ID");
    }

    @Test
    void envReferencesForSecrets() {
        Config config = Config.of(
                Map.of("nas.core.secret", "${env:CORE_SECRET}", "x", "pre-${env:MISSING:-fallback}-post"),
                Map.of("CORE_SECRET", "s3cr$t"));
        assertThat(config.string("nas.core.secret")).isEqualTo("s3cr$t");
        assertThat(config.string("x")).isEqualTo("pre-fallback-post");
        Config broken = Config.of(Map.of("y", "${env:NOT_SET}"));
        assertThatThrownBy(() -> broken.string("y")).hasMessage("y: environment variable NOT_SET is not set");
    }

    @Test
    void typedValues() {
        Config config = Config.of(map(
                "d1", "250ms", "d2", "10s", "d3", "5m", "d4", "2h", "d5", "1d", "d6", "42", "s1", "64k", "s2", "4m",
                "s3", "1g", "s4", "512", "b", "yes", "l", "a, b,,c", "n", "1_000", "e", "large"));
        assertThat(config.duration("d1")).isEqualTo(Duration.ofMillis(250));
        assertThat(config.duration("d2")).isEqualTo(Duration.ofSeconds(10));
        assertThat(config.duration("d3")).isEqualTo(Duration.ofMinutes(5));
        assertThat(config.duration("d4")).isEqualTo(Duration.ofHours(2));
        assertThat(config.duration("d5")).isEqualTo(Duration.ofDays(1));
        assertThat(config.duration("d6")).isEqualTo(Duration.ofMillis(42));
        assertThat(config.bytes("s1")).isEqualTo(65_536);
        assertThat(config.bytes("s2")).isEqualTo(4L << 20);
        assertThat(config.bytes("s3")).isEqualTo(1L << 30);
        assertThat(config.bytes("s4")).isEqualTo(512);
        assertThat(config.bool("b", false)).isTrue();
        assertThat(config.list("l")).containsExactly("a", "b", "c");
        assertThat(config.longValue("n")).isEqualTo(1000);
        assertThat(config.enumValue("e", Profile.class, Profile.SMALL)).isEqualTo(Profile.LARGE);
    }

    private static Map<String, String> map(String... keyValues) {
        Map<String, String> map = new java.util.HashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            map.put(keyValues[i], keyValues[i + 1]);
        }
        return map;
    }

    @Test
    void fallbacks() {
        Config config = Config.of(Map.of());
        assertThat(config.string("x", "d")).isEqualTo("d");
        assertThat(config.integer("x", 3)).isEqualTo(3);
        assertThat(config.longValue("x", 4)).isEqualTo(4);
        assertThat(config.bool("x", true)).isTrue();
        assertThat(config.duration("x", Duration.ZERO)).isZero();
        assertThat(config.bytes("x", 7)).isEqualTo(7);
        assertThat(config.list("x", List.of("z"))).containsExactly("z");
        assertThat(config.enumValue("x", Profile.class, Profile.SMALL)).isEqualTo(Profile.SMALL);
        assertThat(config.has("x")).isFalse();
    }

    @Test
    void errorsNameKeyAndEnvironmentVariable() {
        Config config = Config.of(Map.of("port", "abc", "flag", "maybe", "d", "soon", "s", "lots", "p", "huge"));
        assertThatThrownBy(() -> config.string("missing.key"))
                .isInstanceOf(ConfigException.class)
                .hasMessage("missing.key: required (set it in the properties file or RADIUSWARD_MISSING_KEY)");
        assertThatThrownBy(() -> config.integer("port")).hasMessage("port: expected an integer, got \"abc\"");
        assertThatThrownBy(() -> config.longValue("port")).hasMessageContaining("expected an integer");
        assertThatThrownBy(() -> config.bool("flag", false)).hasMessageContaining("true or false");
        assertThatThrownBy(() -> config.duration("d")).hasMessageContaining("a duration");
        assertThatThrownBy(() -> config.bytes("s")).hasMessageContaining("a size");
        assertThatThrownBy(() -> config.enumValue("p", Profile.class, Profile.SMALL))
                .hasMessageContaining("one of [small, standard, large]");
    }

    @Test
    void namesAndOverrides(@TempDir Path dir) throws IOException {
        Path file = Files.writeString(
                dir.resolve("nas.properties"),
                "nas.core.address=10.0.0.1\nnas.core.secret=a\nnas.edge.address=10.0.0.2\nother=1\n");
        Config config = Config.load(file).with(Map.of("other", "2"));
        assertThat(config.names("nas")).containsExactly("core", "edge");
        assertThat(config.names("nas.")).containsExactly("core", "edge");
        assertThat(config.integer("other")).isEqualTo(2);
        assertThatThrownBy(() -> Config.load(dir.resolve("missing.properties")))
                .hasMessageContaining("cannot read configuration file");
    }

    @Test
    void profiles() {
        assertThat(Profile.SMALL.termLengthParam()).isEqualTo("term-length=2m");
        assertThat(Profile.STANDARD.ipcTermLengthParam()).isEqualTo("term-length=8m");
        assertThat(Profile.LARGE.threadingMode()).isEqualTo("DEDICATED");
        for (Profile p : Profile.values()) {
            assertThat(Integer.bitCount(p.loggingRingSize())).isEqualTo(1);
            assertThat(p.idleStrategy()).isNotNull();
            assertThat(p.maxSessions()).isPositive();
            assertThat(p.pendingRequests()).isPositive();
        }
    }

    @Test
    void commandLineArgs() {
        assertThat(ConfigArgs.files(new String[] {"--config", "a.properties", "--config", "b.properties"}, "u"))
                .containsExactly(Path.of("a.properties"), Path.of("b.properties"));
        assertThatThrownBy(() -> ConfigArgs.files(new String[0], "x --config f"))
                .hasMessage("usage: x --config f");
        assertThatThrownBy(() -> ConfigArgs.files(new String[] {"--config"}, "u"))
                .hasMessage("usage: u");
        assertThatThrownBy(() -> ConfigArgs.files(new String[] {"other"}, "u")).hasMessage("usage: u");
    }
}
