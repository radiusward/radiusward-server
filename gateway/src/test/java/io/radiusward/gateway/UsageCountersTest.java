/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;
import org.junit.jupiter.api.Test;

class UsageCountersTest {

    @Test
    void periods() {
        ZonedDateTime now = ZonedDateTime.of(2027, 1, 15, 8, 0, 0, 0, ZoneId.of("Europe/Prague")); // a Friday
        assertThat(UsageCounters.periodStart(UsageCounters.Reset.DAILY, now))
                .isEqualTo(Instant.parse("2027-01-14T23:00:00Z"));
        assertThat(UsageCounters.periodEnd(UsageCounters.Reset.DAILY, now))
                .isEqualTo(Instant.parse("2027-01-15T23:00:00Z"));
        assertThat(UsageCounters.periodStart(UsageCounters.Reset.WEEKLY, now))
                .isEqualTo(Instant.parse("2027-01-10T23:00:00Z"));
        assertThat(UsageCounters.periodEnd(UsageCounters.Reset.WEEKLY, now))
                .isEqualTo(Instant.parse("2027-01-17T23:00:00Z"));
        assertThat(UsageCounters.periodStart(UsageCounters.Reset.MONTHLY, now))
                .isEqualTo(Instant.parse("2026-12-31T23:00:00Z"));
        assertThat(UsageCounters.periodEnd(UsageCounters.Reset.MONTHLY, now))
                .isEqualTo(Instant.parse("2027-01-31T23:00:00Z"));
        assertThat(UsageCounters.periodStart(UsageCounters.Reset.NEVER, now)).isEqualTo(Instant.EPOCH);
        assertThat(UsageCounters.periodEnd(UsageCounters.Reset.NEVER, now)).isNull();
    }

    @Test
    void configuration() {
        assertThat(UsageCounters.from(Config.of(Map.of()))).isNull();
        UsageCounters c = UsageCounters.from(Config.of(Map.of(
                "auth.counters", "total",
                "auth.counter.total.check", "Max-All-Session",
                "auth.counter.total.reset", "never",
                "auth.counter.total.query", "SELECT 1",
                "auth.counter.sql.url", "jdbc:postgresql://localhost/none")));
        assertThat(c.counters())
                .containsExactly(new UsageCounters.Counter(
                        "total",
                        "Max-All-Session",
                        UsageCounters.Kind.TIME,
                        UsageCounters.Reset.NEVER,
                        "SELECT 1",
                        null));
        assertThat(UsageCounters.zone(Config.of(Map.of("auth.time.zone", "UTC"))))
                .isEqualTo(ZoneId.of("UTC"));
        assertThatThrownBy(() -> UsageCounters.zone(Config.of(Map.of("auth.time.zone", "Mars/Olympus"))))
                .isInstanceOf(ConfigException.class);
        assertThatThrownBy(() -> UsageCounters.from(Config.of(Map.of(
                        "auth.counters", "x",
                        "auth.counter.x.check", "Y",
                        "auth.counter.x.kind", "packets",
                        "auth.counter.sql.url", "jdbc:x"))))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("auth.counter.x.kind");
    }
}
