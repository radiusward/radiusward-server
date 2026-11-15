/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SinkContextTest {

    private final SinkContext context = new SinkContext(
            "archive", 0, Map.of("retention", "12h", "timeout", "3", "max", "64k", "bad", "soon"), null);

    @Test
    void durationsAndSizesWithTheSinksNameInErrors() {
        assertThat(context.duration("retention", "90d", null)).isEqualTo(Duration.ofHours(12));
        assertThat(context.duration("missing", "90d", null)).isEqualTo(Duration.ofDays(90));
        assertThat(context.duration("timeout", "3s", ChronoUnit.SECONDS)).isEqualTo(Duration.ofSeconds(3));
        assertThatThrownBy(() -> context.duration("timeout", "3s", null))
                .hasMessage("sink.archive.timeout: expected a duration with a unit (ms, s, m, h, d), got 3");
        assertThatThrownBy(() -> context.duration("bad", "1s", null)).hasMessageStartingWith("sink.archive.bad: ");
        assertThat(context.bytes("max", "1m")).isEqualTo(64 << 10);
        assertThat(context.bytes("missing", "1m")).isEqualTo(1 << 20);
        assertThatThrownBy(() -> context.bytes("bad", "1m")).hasMessageStartingWith("sink.archive.bad: ");
    }
}
