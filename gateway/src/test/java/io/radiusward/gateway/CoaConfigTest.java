/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@code coa.*} and {@code nas.<name>.coa.*} (ADR 0036). */
class CoaConfigTest {

    @Test
    void offByDefault() {
        assertThat(CoaConfig.from(Config.of(Map.of())).enabled()).isFalse();
    }

    @Test
    void keys() {
        CoaConfig c = CoaConfig.from(Config.of(Map.of(
                "coa.enabled", "true",
                "coa.timeout", "1s",
                "coa.retries", "4",
                "coa.api.token", "0123456789abcdef",
                "coa.simultaneous.use", "disconnect-oldest",
                "coa.simultaneous.use.wait", "2s",
                "nas.core.address", "10.0.0.1",
                "nas.core.coa.address", "10.0.0.2",
                "nas.core.coa.port", "1700",
                "nas.core.coa.secret", "other")));
        assertThat(c.timeout()).isEqualTo(Duration.ofSeconds(1));
        assertThat(c.retries()).isEqualTo(4);
        assertThat(c.token()).isEqualTo("0123456789abcdef");
        assertThat(c.disconnectOldest()).isTrue();
        assertThat(c.simultaneousUseWait()).isEqualTo(Duration.ofSeconds(2));
        CoaConfig.Target core = c.target("core");
        assertThat(core.address().getHostAddress()).isEqualTo("10.0.0.2");
        assertThat(core.port()).isEqualTo(1700);
        assertThat(new String(core.secret(), StandardCharsets.UTF_8)).isEqualTo("other");
        assertThat(c.target("unknown").port()).isEqualTo(CoaConfig.DEFAULT_PORT);
        assertThat(CoaConfig.from(Config.of(Map.of("coa.enabled", "true"))).token())
                .as("no token: no HTTP API")
                .isNull();
    }

    @Test
    void mistakes() {
        for (String[] wrong :
                new String[][] {{"coa.retries", "11"}, {"coa.api.token", "short"}, {"coa.simultaneous.use", "kick"}}) {
            assertThatThrownBy(() -> CoaConfig.from(Config.of(Map.of("coa.enabled", "true", wrong[0], wrong[1]))))
                    .as(wrong[0])
                    .hasMessageContaining(wrong[0]);
        }
    }
}
