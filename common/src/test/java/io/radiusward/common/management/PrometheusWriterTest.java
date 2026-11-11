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
    void writesHistograms() {
        String text = new PrometheusWriter()
                .family("radiusward_lookup_seconds", "histogram", "Look-ups")
                .histogram(new double[] {0.01, 0.1}, new long[] {2, 5, 6}, 0.75, "store", "sql")
                .finish();
        assertThat(text).isEqualTo("""
                # HELP radiusward_lookup_seconds Look-ups
                # TYPE radiusward_lookup_seconds histogram
                radiusward_lookup_seconds_bucket{store="sql",le="0.01"} 2
                radiusward_lookup_seconds_bucket{store="sql",le="0.1"} 5
                radiusward_lookup_seconds_bucket{store="sql",le="+Inf"} 6
                radiusward_lookup_seconds_sum{store="sql"} 0.75
                radiusward_lookup_seconds_count{store="sql"} 6
                """);
        assertValid(text);
        assertThatThrownBy(() -> new PrometheusWriter()
                        .family("radiusward_h", "histogram", "h")
                        .histogram(new double[] {1}, new long[] {1}, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> assertValid("# TYPE radiusward_c counter\nradiusward_c_bucket 1"))
                .as("only a histogram's family has _bucket samples")
                .isInstanceOf(IllegalArgumentException.class);
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
        PrometheusWriter jvm = new PrometheusWriter();
        JvmMetrics.write(jvm);
        assertThat(jvm.finish()).contains("radiusward_jvm_buffer_used_bytes{pool=\"direct\"} ");
        assertValid(jvm.finish());
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
                .contains("radiusward_jvm_threads ")
                .contains("radiusward_process_cpu_seconds_total ")
                .contains("radiusward_process_cpus ");
    }
}
