/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.units;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Durations, sizes, lists and hex as written in settings, parsed the same way by the main configuration, the sinks
 * and the identity stores: {@code 250ms}, {@code 10s}, {@code 5m}, {@code 2h}, {@code 1d}; {@code 512}, {@code 64k},
 * {@code 4m}, {@code 1g} (an optional {@code b}); {@code a, b, c}; {@code 0x00ff…}. Case and spaces between number
 * and unit do not matter.
 */
public final class Units {

    private static final Pattern DURATION = Pattern.compile("(\\d+)\\s*(ms|s|m|h|d)?");
    private static final Pattern SIZE = Pattern.compile("(\\d+)\\s*([kmg])?b?");
    private static final Pattern COMMAS = Pattern.compile(",");
    private static final Pattern COMMAS_OR_SPACES = Pattern.compile("[,\\s]+");

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

    /** The items of a comma-separated list, trimmed; empty items are left out ({@code ""} is the empty list). */
    public static List<String> list(String text) {
        return split(text, COMMAS);
    }

    /** As {@link #list}, with spaces separating items too: for values that cannot contain one, such as URLs. */
    public static List<String> words(String text) {
        return split(text, COMMAS_OR_SPACES);
    }

    private static List<String> split(String text, Pattern separator) {
        return separator
                .splitAsStream(text)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * Bytes written as hex digits, with or without {@code 0x}, in either case.
     *
     * @param length the number of bytes expected; {@code -1}: any
     * @throws IllegalArgumentException if {@code text} is not hex or not {@code length} bytes
     */
    public static byte[] hex(String text, int length) {
        String digits = text.trim();
        if (digits.startsWith("0x") || digits.startsWith("0X")) {
            digits = digits.substring(2);
        }
        byte[] bytes;
        try {
            bytes = HexFormat.of().parseHex(digits);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("expected hex digits, got " + text, e);
        }
        if (length >= 0 && bytes.length != length) {
            throw new IllegalArgumentException("expected " + length + " bytes of hex, got " + bytes.length);
        }
        return bytes;
    }
}
