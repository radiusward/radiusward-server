/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PortsTest {

    @Test
    void eachForkDrawsFromItsOwnShare() {
        String before = System.getProperty("radiusward.fork");
        try {
            for (int fork = 1; fork <= Ports.FORK_SLOTS; fork++) {
                System.setProperty("radiusward.fork", Integer.toString(fork));
                for (int i = 0; i < 20; i++) {
                    int base = Ports.freePortBase(3);
                    int first = (base - 20_000) / 100;
                    assertThat(first / 30)
                            .as("the cluster's first step in this fork's quarter")
                            .isEqualTo(fork - 1);
                    assertThat((first + 2) / 30)
                            .as("its last member's step too: no overlap with another fork")
                            .isEqualTo(fork - 1);
                    int port = Ports.freePort();
                    assertThat((port - 10_000) / 2_500).isEqualTo(fork - 1);
                }
            }
        } finally {
            if (before == null) {
                System.clearProperty("radiusward.fork");
            } else {
                System.setProperty("radiusward.fork", before);
            }
        }
    }

    @Test
    void awaitReturnsOnceTrueAndFailsWithTheReasonOtherwise() {
        long[] calls = {0};
        Await.until(java.time.Duration.ofSeconds(5), "third call", () -> ++calls[0] >= 3);
        assertThat(calls[0]).isEqualTo(3);
        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> Await.until(java.time.Duration.ofMillis(100), "never", () -> false))
                .hasMessage("timed out waiting for: never");
    }

    @Test
    void awaitValueReturnsTheFirstNonNullResult() {
        int[] calls = {0};
        assertThat(Await.value(java.time.Duration.ofSeconds(5), "second call", () -> ++calls[0] < 2 ? null : "ready"))
                .isEqualTo("ready");
    }
}
