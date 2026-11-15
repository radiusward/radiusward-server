/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.units;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Durations and sizes as written in settings, parsed the same way by the main configuration, the sinks and the
 * identity stores: {@code 250ms}, {@code 10s}, {@code 5m}, {@code 2h}, {@code 1d}; {@code 512}, {@code 64k},
 * {@code 4m}, {@code 1g} (an optional {@code b}). Case and spaces between number and unit do not matter.
 */
public final class Units {

    private static final Pattern DURATION = Pattern.compile("(\\d+)\\s*(ms|s|m|h|d)?");
    private static final Pattern SIZE = Pattern.compile("(\\d+)\\s*([kmg])?b?");

    private Units() {}

    /**
     * A duration.
     *
     * @param bare the unit of a number without one; {@code null}: a unit is required, except for {@code 0}
     * @throws IllegalArgumentException if {@code text} is not a duration
     */
    public static Duration duration(String text, ChronoUnit bare) {
        Matcher m = DURATION.matcher(text.trim().toLowerCase(Locale.ROOT));
        if (!m.matches()) {
            throw new IllegalArgumentException("expected a duration such as 500ms, 10s, 5m, 2h or 1d, got " + text);
        }
        long n = Long.parseLong(m.group(1));
        if (m.group(2) == null) {
            if (bare == null && n != 0) {
                throw new IllegalArgumentException("expected a duration with a unit (ms, s, m, h, d), got " + text);
            }
            return bare == null ? Duration.ZERO : Duration.of(n, bare);
        }
        return switch (m.group(2)) {
            case "ms" -> Duration.ofMillis(n);
            case "s" -> Duration.ofSeconds(n);
            case "m" -> Duration.ofMinutes(n);
            case "h" -> Duration.ofHours(n);
            default -> Duration.ofDays(n);
        };
    }

    /**
     * A size in bytes: a plain number, or with {@code k}, {@code m}, {@code g} (powers of 1024).
     *
     * @throws IllegalArgumentException if {@code text} is not a size
     */
    public static long bytes(String text) {
        Matcher m = SIZE.matcher(text.trim().toLowerCase(Locale.ROOT));
        if (!m.matches()) {
            throw new IllegalArgumentException("expected a size such as 512, 64k, 4m or 1g, got " + text);
        }
        long n = Long.parseLong(m.group(1));
        if (m.group(2) == null) {
            return n;
        }
        return switch (m.group(2)) {
            case "k" -> n << 10;
            case "m" -> n << 20;
            default -> n << 30;
        };
    }
}
