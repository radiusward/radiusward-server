/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.common.management;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PrometheusWriterTest {

    static void assertValid(String text) {
        PrometheusWriter.validate(text);
    }

    @Test
    void writesFamiliesSamplesAndEscapedLabels() {
        String text = new PrometheusWriter()
                .counter("radiusward_x_total", "Things\nwith a newline")
                .sample(3, "a", "1", "b", "quo\"te\\")
                .sample(4.5)
                .gauge("radiusward_y_bytes", "Size")
                .sample(Double.NaN)
                .counter("radiusward_x_total", "ignored the second time")
                .sample(Double.POSITIVE_INFINITY, "a", "2")
                .finish();
        assertThat(text).isEqualTo("""
                # HELP radiusward_x_total Things\\nwith a newline
                # TYPE radiusward_x_total counter
                radiusward_x_total{a="1",b="quo\\"te\\\\"} 3
                radiusward_x_total 4.5
                # HELP radiusward_y_bytes Size
                # TYPE radiusward_y_bytes gauge
                radiusward_y_bytes NaN
                radiusward_x_total{a="2"} +Inf
                """);
        assertValid(text);
        JvmMetrics.write(new PrometheusWriter());
    }

    @Test
    void validateFindsBrokenText() {
        assertThatThrownBy(() -> PrometheusWriter.validate("radiusward_x 1")).hasMessageContaining("before its TYPE");
        assertThatThrownBy(() -> PrometheusWriter.validate("# TYPE a gauge\n# TYPE a gauge"))
                .hasMessageContaining("TYPE twice");
        assertThatThrownBy(() -> PrometheusWriter.validate("# TYPE a gauge\na{x=1} 2"))
                .hasMessageContaining("invalid");
    }

    @Test
    void rejectsInvalidUse() {
        assertThatThrownBy(() -> new PrometheusWriter().sample(1)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new PrometheusWriter().gauge("bad-name", "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PrometheusWriter().gauge("ok", "x").sample(1, "odd"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void jvmMetricsAreValid() {
        PrometheusWriter w = new PrometheusWriter();
        JvmMetrics.write(w);
        String text = w.finish();
        assertValid(text);
        assertThat(text)
                .contains("radiusward_jvm_memory_used_bytes{area=\"heap\"}")
                .contains("radiusward_jvm_threads ");
    }
}
