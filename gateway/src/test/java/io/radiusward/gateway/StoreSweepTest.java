/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** The sweep's thread: a failing sweep is logged and retried later; stopping interrupts the wait between sweeps. */
class StoreSweepTest {

    @Test
    void aFailedSweepWaitsForTheNextAndStoppingEndsTheWait() throws Exception {
        // no CoA service: the sweep fails at once and the thread sleeps for the hour to the next one
        StoreSweep sweep = new StoreSweep(new CoaConfig.Sweep(true, Duration.ofHours(1), 20, false), null, null);
        sweep.start();
        Thread.sleep(200);
        assertThat(sweep.alive()).isTrue();
        sweep.stop();
        long deadline = System.nanoTime() + 2_000_000_000L;
        while (sweep.alive() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertThat(sweep.alive()).as("interrupted in its wait").isFalse();
    }
}
