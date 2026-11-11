/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.management.PrometheusWriter;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/** Identity store look-ups as a histogram and by result, and Access-Rejects by cause. */
class StoreLookupsTest {

    @Test
    void histogramIsCumulativeAndCountsResults() {
        StoreLookups s = new StoreLookups();
        s.record(200_000, StoreLookups.FOUND); // 0.2 ms: the first bucket
        s.record(3_000_000, StoreLookups.NOT_FOUND); // 3 ms: le 0.005
        s.record(10_000_000_000L, StoreLookups.UNAVAILABLE); // 10 s: only +Inf
        long[] c = s.cumulative();
        assertThat(c[0]).isEqualTo(1);
        assertThat(c[3]).as("le 0.005").isEqualTo(2);
        assertThat(c[c.length - 2]).as("le 2.5").isEqualTo(2);
        assertThat(c[c.length - 1]).isEqualTo(3);
        assertThat(s.seconds()).isEqualTo(10.0032);
        assertThat(s.result(StoreLookups.UNAVAILABLE)).isEqualTo(1);

        TreeMap<String, StoreLookups> stores = new TreeMap<>();
        stores.put("sql", s);
        PrometheusWriter w = new PrometheusWriter();
        StoreLookups.write(w, "2", stores);
        String text = w.finish();
        assertThat(text)
                .contains("radiusward_gateway_store_lookups_total{gateway=\"2\",store=\"sql\",result=\"not_found\"} 1")
                .contains("radiusward_gateway_store_lookup_seconds_bucket{gateway=\"2\",store=\"sql\",le=\"+Inf\"} 3")
                .contains("radiusward_gateway_store_lookup_seconds_count{gateway=\"2\",store=\"sql\"} 3");
        PrometheusWriter.validate(text);

        PrometheusWriter none = new PrometheusWriter();
        StoreLookups.write(none, "2", new TreeMap<>());
        assertThat(none.finish()).as("no stores, no families").isEmpty();
    }

    @Test
    void rejectsAreCountedByCause() {
        AuthStats stats = new AuthStats();
        stats.rejected("user not in any store: ");
        stats.rejected("user not in any store: ");
        stats.rejected(null);
        stats.rejected("wrong TOTP code");
        assertThat(stats.rejectsByCause())
                .containsExactly(
                        java.util.Map.entry(AuthStats.UNKNOWN_CAUSE, 1L),
                        java.util.Map.entry("user not in any store", 2L),
                        java.util.Map.entry("wrong TOTP code", 1L));
    }
}
