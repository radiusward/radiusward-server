/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

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
    private final OnceLogger once;

    CheckItems(Dictionary dictionary, LongSupplier clockMillis, OnceLogger once) {
        this.dictionary = dictionary;
        this.clockMillis = clockMillis;
        this.once = once;
    }

    /**
     * Evaluates check items; collects passwords.
     *
     * @param zone the zone of dates without one ({@code auth.time.zone})
     * @return the {@code Auth-Type} ("" if none), or {@code null} if a condition fails
     */
    String checks(List<AttributeItem> items, RadiusPacket request, List<AttributeItem> passwords, ZoneId zone) {
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
                Instant expires = date(item.value(), zone);
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
                : AttributeText.decode(def, request.buffer(), request.valueOffset(at), request.valueLength(at));
        String expected = item.value();
        try {
            Pattern pattern = ValueComparison.isPattern(item.op()) ? Pattern.compile(expected) : null;
            return ValueComparison.holds(item.op(), actual, expected, pattern);
        } catch (PatternSyntaxException e) {
            once.warn("regex:" + expected, "check item {}: invalid pattern, the condition fails", item.attribute());
            return false;
        }
    }

    /** A date as the stores write it; {@code zone}: the zone of dates without one. */
    Instant date(String text, ZoneId zone) {
        String t = text.trim().replaceAll("\\s+", " ");
        try {
            return Instant.parse(t);
        } catch (DateTimeParseException ignored) {
            // not ISO-8601
        }
        for (DateTimeFormatter f : DATES) {
            try {
                return LocalDateTime.parse(t, f).atZone(zone).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        for (DateTimeFormatter f : DAYS) {
            try {
                return LocalDate.parse(t, f).atStartOfDay(zone).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        try {
            return LocalDate.parse(t).atStartOfDay(zone).toInstant();
        } catch (DateTimeParseException e) {
            return null; // fail closed
        }
    }
}
