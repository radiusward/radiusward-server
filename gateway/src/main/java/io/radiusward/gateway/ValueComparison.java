/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.util.regex.Pattern;

/**
 * How a request's attribute value compares with a configured one, the same for check items (ADR 0021) and rules
 * (ADR 0051): {@code ==}, {@code !=}, {@code =~} and {@code !~} (a regular expression found in the value), and
 * {@code <}, {@code >}, {@code <=}, {@code >=} as whole numbers. A missing value equals nothing, matches no pattern and
 * compares as no number.
 */
final class ValueComparison {

    private ValueComparison() {}

    /**
     * @param actual the request's value, {@code null} if absent
     * @param pattern {@code expected} compiled, for {@code =~} and {@code !~}
     */
    static boolean holds(String op, String actual, String expected, Pattern pattern) {
        return switch (op) {
            case "==" -> expected.equals(actual);
            case "!=" -> !expected.equals(actual);
            case "=~" -> actual != null && pattern.matcher(actual).find();
            case "!~" -> actual == null || !pattern.matcher(actual).find();
            default -> numeric(op, actual, expected);
        };
    }

    /** Whether {@code op} compares with a regular expression. */
    static boolean isPattern(String op) {
        return op.equals("=~") || op.equals("!~");
    }

    private static boolean numeric(String op, String actual, String expected) {
        try {
            long a = Long.parseLong(actual);
            long e = Long.parseLong(expected);
            return switch (op) {
                case "<" -> a < e;
                case ">" -> a > e;
                case "<=" -> a <= e;
                default -> a >= e;
            };
        } catch (NumberFormatException | NullPointerException ex) {
            return false;
        }
    }
}
