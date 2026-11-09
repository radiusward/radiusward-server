/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class EventKeysTest {

    private static final UnsafeBuffer SESSION = new UnsafeBuffer("00000A1B".getBytes(StandardCharsets.US_ASCII));

    /**
     * Pinned layout: changing it would make gateways compute keys the cluster has never seen, so every
     * retransmit after an upgrade would count as new. Values come from an independent reference implementation.
     */
    @Test
    void pinnedVectors() {
        EventKeys keys = new EventKeys();
        keys.compute(1001, 3, 3, 300, 1_780_000_300L, 1_048_576, 52_428_800, SESSION, 0, 8);
        assertThat(keys.sessionHi()).isEqualTo(-3631950616133683077L);
        assertThat(keys.sessionLo()).isEqualTo(-2752781867325709057L);
        assertThat(keys.exactHi()).isEqualTo(154470058279179513L);
        assertThat(keys.exactLo()).isEqualTo(-2472904477151954232L);
    }

    @Test
    void sessionKeyIgnoresEventDetails() {
        EventKeys a = new EventKeys();
        EventKeys b = new EventKeys();
        a.compute(1001, 1, 2, 0, 1_780_000_000L, 0, 0, SESSION, 0, 8);
        b.compute(1001, 2, 3, 900, 1_780_000_900L, 5, 6, SESSION, 0, 8);
        assertThat(b.sessionHi()).isEqualTo(a.sessionHi());
        assertThat(b.sessionLo()).isEqualTo(a.sessionLo());
        assertThat(b.exactHi()).isNotEqualTo(a.exactHi());
    }

    @Test
    void nasIsPartOfBothKeys() {
        EventKeys a = new EventKeys();
        EventKeys b = new EventKeys();
        a.compute(1, 1, 0, 0, 0, 0, 0, SESSION, 0, 8);
        b.compute(2, 1, 0, 0, 0, 0, 0, SESSION, 0, 8);
        assertThat(b.sessionHi()).isNotEqualTo(a.sessionHi());
        assertThat(b.exactHi()).isNotEqualTo(a.exactHi());
    }

    @Test
    void eventsWithoutSessionId() {
        EventKeys keys = new EventKeys();
        keys.compute(7, 7, 2, 0, 1_780_000_000L, 0, 0, SESSION, 0, 0);
        long first = keys.exactHi();
        keys.compute(7, 7, 2, 0, 1_780_000_001L, 0, 0, SESSION, 0, 0);
        assertThat(keys.exactHi()).isNotEqualTo(first);
    }

    private static final UnsafeBuffer AP_1 = new UnsafeBuffer("ap-1".getBytes(StandardCharsets.US_ASCII));
    private static final UnsafeBuffer AP_2 = new UnsafeBuffer("ap-2".getBytes(StandardCharsets.US_ASCII));

    /** Regression vectors of the device layout (ADR 0019): nasId, length, identity, then as before. */
    @Test
    void pinnedDeviceVectors() {
        EventKeys keys = new EventKeys();
        keys.compute(1001, AP_1, 4, 3, 3, 300, 1_780_000_300L, 1_048_576, 52_428_800, SESSION, 0, 8);
        assertThat(keys.sessionHi()).isEqualTo(-4984180112865789693L);
        assertThat(keys.sessionLo()).isEqualTo(-8261713462200549033L);
        assertThat(keys.exactHi()).isEqualTo(6347246374314411620L);
        assertThat(keys.exactLo()).isEqualTo(6255961933786324328L);
        assertThat(keys.scope()).isEqualTo(-1810459823);
    }

    @Test
    void withoutADeviceTheKeysAndScopeAreAsBefore() {
        EventKeys plain = new EventKeys();
        EventKeys none = new EventKeys();
        plain.compute(1001, 3, 3, 300, 1_780_000_300L, 1, 2, SESSION, 0, 8);
        none.compute(1001, AP_1, 0, 3, 3, 300, 1_780_000_300L, 1, 2, SESSION, 0, 8);
        assertThat(none.sessionHi()).isEqualTo(plain.sessionHi());
        assertThat(none.exactLo()).isEqualTo(plain.exactLo());
        assertThat(plain.scope()).isEqualTo(1001);
        assertThat(none.scope()).isEqualTo(1001);
    }

    @Test
    void devicesNeverShareASessionAndHaveTheirOwnScope() {
        EventKeys a = new EventKeys();
        EventKeys b = new EventKeys();
        EventKeys entry = new EventKeys();
        a.compute(1001, AP_1, 4, 1, 0, 0, 0, 0, 0, SESSION, 0, 8);
        b.compute(1001, AP_2, 4, 1, 0, 0, 0, 0, 0, SESSION, 0, 8);
        entry.compute(1001, 1, 0, 0, 0, 0, 0, SESSION, 0, 8);
        assertThat(a.sessionHi()).isNotEqualTo(b.sessionHi()).isNotEqualTo(entry.sessionHi());
        assertThat(a.exactHi()).isNotEqualTo(b.exactHi()).isNotEqualTo(entry.exactHi());
        assertThat(a.scope()).isNotEqualTo(b.scope()).isNotEqualTo(1001);
        // the scope depends on the device only, not on the session or event
        int scope = a.scope();
        a.compute(1001, AP_1, 4, 3, 1, 60, 5, 6, 7, SESSION, 0, 3);
        assertThat(a.scope()).isEqualTo(scope);
    }
}
