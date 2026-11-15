/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A user's or group's check items against an Access-Request: passwords are collected, {@code Auth-Type} and
 * {@code Expiration} are applied, comparisons ({@code ==}, {@code !=}, {@code =~}, {@code !~}, {@code <} …) test the
 * request's attributes. A condition that cannot be evaluated fails (fail closed).
 */
final class CheckItems {

    private static final Set<String> COMPARISONS = Set.of("==", "!=", "=~", "!~", "<", ">", "<=", ">=");
    private static final DateTimeFormatter[] DATES = {
        DateTimeFormatter.ofPattern("MMM d yyyy HH:mm:ss", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("MMM d yyyy HH:mm", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("d MMM yyyy HH:mm:ss", Locale.ENGLISH)
    };
    private static final DateTimeFormatter[] DAYS = {
        DateTimeFormatter.ofPattern("MMM d yyyy", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH)
    };

    private final Dictionary dictionary;
    private final LongSupplier clockMillis;
    private final Supplier<ZoneId> zone;
    private final OnceLogger once;

    /** @param zone the zone of dates without one (Login-Time's zone, {@code auth.counter.zone}) */
    CheckItems(Dictionary dictionary, LongSupplier clockMillis, Supplier<ZoneId> zone, OnceLogger once) {
        this.dictionary = dictionary;
        this.clockMillis = clockMillis;
        this.zone = zone;
        this.once = once;
    }

    /**
     * Evaluates check items; collects passwords.
     *
     * @return the {@code Auth-Type} ("" if none), or {@code null} if a condition fails
     */
    String checks(List<AttributeItem> items, RadiusPacket request, List<AttributeItem> passwords) {
        String authType = "";
        for (AttributeItem item : items) {
            String name = item.attribute();
            if (PasswordCheck.isPassword(name)
                    || name.equalsIgnoreCase("NT-Password")
                    || name.equalsIgnoreCase("LM-Password")) {
                passwords.add(item);
            } else if (name.equalsIgnoreCase("Auth-Type")) {
                authType = item.value();
            } else if (name.equalsIgnoreCase("Expiration")) {
                Instant expires = date(item.value());
                if (expires == null
                        || !Instant.ofEpochMilli(clockMillis.getAsLong()).isBefore(expires)) {
                    return null;
                }
            } else if (name.equalsIgnoreCase(StoreAccessHandler.SIMULTANEOUS_USE)) {
                continue; // applied after authentication, through the cluster (#limit)
            } else if (COMPARISONS.contains(item.op()) && !compare(item, request)) {
                return null;
            }
            // other ':=', '=', '+=' items are configuration items without meaning here
        }
        return authType;
    }

    private boolean compare(AttributeItem item, RadiusPacket request) {
        AttributeDef def = dictionary.find(item.attribute());
        if (def == null || def.vendorId() != 0) {
            once.warn(
                    "compare:" + item.attribute(),
                    "check item {} cannot be compared (unknown or vendor-specific):" + " the condition fails",
                    item.attribute());
            return false;
        }
        int at = request.findAttribute(def.number());
        String actual = at < 0
                ? null
                : AttributeText.decode(
                        def, request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
        String expected = item.value();
        try {
            return switch (item.op()) {
                case "==" -> expected.equals(actual);
                case "!=" -> !expected.equals(actual);
                case "=~" ->
                    actual != null && Pattern.compile(expected).matcher(actual).find();
                case "!~" ->
                    actual == null || !Pattern.compile(expected).matcher(actual).find();
                default -> numeric(item.op(), actual, expected);
            };
        } catch (PatternSyntaxException e) {
            once.warn("regex:" + expected, "check item {}: invalid pattern, the condition fails", item.attribute());
            return false;
        }
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

    Instant date(String text) {
        String t = text.trim().replaceAll("\\s+", " ");
        try {
            return Instant.parse(t);
        } catch (DateTimeParseException ignored) {
            // not ISO-8601
        }
        for (DateTimeFormatter f : DATES) {
            try {
                return LocalDateTime.parse(t, f).atZone(zone.get()).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        for (DateTimeFormatter f : DAYS) {
            try {
                return LocalDate.parse(t, f).atStartOfDay(zone.get()).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        try {
            return LocalDate.parse(t).atStartOfDay(zone.get()).toInstant();
        } catch (DateTimeParseException e) {
            return null; // fail closed
        }
    }
}
