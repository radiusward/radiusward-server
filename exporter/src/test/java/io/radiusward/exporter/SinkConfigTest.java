/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SinkConfigTest {

    private static final Map<String, String> PG =
            Map.of("export.sinks", "pg", "sink.pg.type", "postgres", "sink.pg.url", "jdbc:postgresql://db/radius");

    @Test
    void defaultsFollowThePlan() {
        SinkConfig pg = SinkConfig.from(Config.of(PG)).get(0);
        assertThat(pg.required()).isTrue();
        assertThat(pg.detachOnMaxLag()).isFalse();
        assertThat(pg.maxLagMs()).isEqualTo(4 * 3_600_000L);
        assertThat(pg.batchRows()).isEqualTo(5000);
        assertThat(pg.settings()).containsEntry("url", "jdbc:postgresql://db/radius");
    }

    @Test
    void anEmptyListDisablesTheExporter() {
        assertThat(SinkConfig.from(Config.of(PG, Map.of("RADIUSWARD_EXPORT_SINKS", ""))))
                .isEmpty();
        assertThat(SinkConfig.from(Config.of(Map.of()))).isEmpty();
        assertThat(ExportConfig.from(Config.of(PG, Map.of("RADIUSWARD_EXPORT_SINKS", " ")))
                        .enabled())
                .isFalse();
    }

    @Test
    void optionalSinksDetachAndInvalidCombinationsAreRejected() {
        SinkConfig optional = SinkConfig.from(Config.of(PG, Map.of("RADIUSWARD_SINK_PG_REQUIRED", "false")))
                .get(0);
        assertThat(optional.detachOnMaxLag()).isTrue();
        assertThatThrownBy(() -> SinkConfig.from(Config.of(
                        PG, Map.of("RADIUSWARD_SINK_PG_REQUIRED", "false", "RADIUSWARD_SINK_PG_ON_MAX_LAG", "block"))))
                .hasMessageContaining("needs sink.pg.required=true");
        assertThatThrownBy(() -> SinkConfig.from(Config.of(Map.of("export.sinks", "Bad Name"))))
                .hasMessageContaining("must be at most 32 characters");
        assertThatThrownBy(() -> SinkConfig.from(Config.of(Map.of("export.sinks", "x"))))
                .hasMessageContaining("sink.x.type is required");
    }
}
