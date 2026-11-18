/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class ValueComparisonTest {

    private static boolean holds(String op, String actual, String expected) {
        return ValueComparison.holds(
                op, actual, expected, ValueComparison.isPattern(op) ? Pattern.compile(expected) : null);
    }

    @Test
    void equalityAndPatterns() {
        assertThat(holds("==", "a", "a")).isTrue();
        assertThat(holds("==", null, "a")).isFalse();
        assertThat(holds("!=", null, "a")).as("a missing value differs").isTrue();
        assertThat(holds("=~", "Cisco-ISR", "^Cisco")).isTrue();
        assertThat(holds("=~", null, ".*")).isFalse();
        assertThat(holds("!~", null, ".*"))
                .as("a missing value matches no pattern")
                .isTrue();
        assertThat(holds("!~", "Juniper", "^Cisco")).isTrue();
    }

    @Test
    void wholeNumbers() {
        assertThat(holds("<", "3", "10")).as("as numbers, not text").isTrue();
        assertThat(holds(">", "10", "3")).isTrue();
        assertThat(holds("<=", "3", "3")).isTrue();
        assertThat(holds(">=", "2", "3")).isFalse();
        assertThat(holds("<", "x", "3")).as("not a number").isFalse();
        assertThat(holds(">", null, "3")).as("missing").isFalse();
        assertThat(ValueComparison.isPattern("==")).isFalse();
    }
}
