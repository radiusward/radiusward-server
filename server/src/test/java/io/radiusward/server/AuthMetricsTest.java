/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AuthMetricsTest {

    @Test
    void eapOutcomesAreCountedPerMethod() {
        AuthMetrics metrics = new AuthMetrics();
        metrics.eapOutcome(EapConfig.type("peap"), AuthMetrics.SUCCEEDED);
        metrics.eapOutcome(EapConfig.type("peap"), AuthMetrics.SUCCEEDED);
        metrics.eapOutcome(EapConfig.type("peap"), AuthMetrics.STORE_UNAVAILABLE);
        metrics.eapOutcome(EapConfig.type("ttls"), AuthMetrics.TOO_MANY_ROUNDS);
        assertThat(metrics.eapOutcome("peap", "succeeded")).isEqualTo(2);
        assertThat(metrics.eapOutcome("peap", "store_unavailable")).isEqualTo(1);
        assertThat(metrics.eapOutcome("peap", "failed")).isZero();
        assertThat(metrics.eapOutcome("ttls", "too_many_rounds")).isEqualTo(1);
        assertThat(metrics.eapOutcome("tls", "succeeded")).isZero();
    }

    @Test
    void eachStoreHasOneSetOfLookupCounters() {
        AuthMetrics metrics = new AuthMetrics();
        assertThat(metrics.lookups("sql")).isSameAs(metrics.lookups("sql"));
        assertThat(metrics.lookups("sql")).isNotSameAs(metrics.lookups("file"));
    }
}
