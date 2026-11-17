/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.codec.RadiusPacket;
import java.time.Instant;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * What limits an authorized user (ADR 0049, ADR 0060, ADR 0023): Expiration, Expire-After, Login-Time and usage
 * counters, which reject or cap the Accept's Session-Timeout, and Simultaneous-Use, which the cluster counts.
 */
final class Restrictions {

    private static final int USER_NAME = 1;
    private static final int CALLING_STATION_ID = 31;

    private final CheckItems checkItems;
    private final LongSupplier clockMillis;
    private final OnceLogger once;

    Restrictions(CheckItems checkItems, LongSupplier clockMillis, OnceLogger once) {
        this.checkItems = checkItems;
        this.clockMillis = clockMillis;
        this.once = once;
    }

    /** The zone of Login-Time, counter periods and dates without one. */
    java.time.ZoneId zone() {
        return zone;
    }

    private volatile UsageCounters counters;
    private volatile java.time.ZoneId zone = java.time.ZoneId.systemDefault();

    /** Usage counters ({@code auth.counters}) and the zone of Login-Time and counter periods. */
    void limits(UsageCounters counters, java.time.ZoneId zone) {
        this.counters = counters;
        this.zone = zone;
    }

    void collect(List<AttributeItem> checks, List<AttributeItem> into) {
        UsageCounters c = counters;
        for (AttributeItem item : checks) {
            String name = item.attribute();
            if (name.equalsIgnoreCase("Expiration")
                    || name.equalsIgnoreCase("Expire-After")
                    || name.equalsIgnoreCase("Login-Time")
                    || name.equalsIgnoreCase("Pool-Name")
                    || name.equalsIgnoreCase(TotpFactor.SECRET)) {
                into.add(item);
            } else if (c != null
                    && c.counters().stream().anyMatch(k -> k.check().equalsIgnoreCase(name))) {
                into.add(item);
            }
        }
    }

    /**
     * Expiration, Login-Time and usage counters of the authorized user: outside a login window or over a limit is a
     * reject; otherwise the Accept's Session-Timeout is cut to the earliest end (expiry, the window's end, the time
     * left on a time counter or its period). A counter that cannot be read leaves the request unanswered.
     */
    int restrict(AccessContext context, String user, StoreAccessHandler.Authorization a) {
        if (a.restrictions().isEmpty()) {
            return AccessHandler.ACCEPT;
        }
        Instant now = Instant.ofEpochMilli(clockMillis.getAsLong());
        java.time.ZonedDateTime local = now.atZone(zone);
        long cap = Long.MAX_VALUE;
        for (AttributeItem item : a.restrictions()) {
            String name = item.attribute();
            if (name.equalsIgnoreCase("Expiration")) {
                Instant expires = checkItems.date(item.value());
                if (expires == null || !now.isBefore(expires)) {
                    StoreAccessHandler.because(context, "expired: ", item.value());
                    return AccessHandler.REJECT;
                }
                cap = Math.min(
                        cap,
                        Math.max(1, java.time.Duration.between(now, expires).getSeconds()));
            } else if (name.equalsIgnoreCase("Expire-After")) {
                long after = expireAfter(context, user, item, now);
                if (after < 0) {
                    return after == -2 ? AccessHandler.DROP : AccessHandler.REJECT;
                }
                cap = Math.min(cap, Math.max(1, after));
            } else if (name.equalsIgnoreCase("Pool-Name") || name.equalsIgnoreCase(TotpFactor.SECRET)) {
                continue; // #assignAddress, #totp
            } else if (name.equalsIgnoreCase("Login-Time")) {
                LoginTime window = LoginTime.parse(item.value());
                if (window == null) {
                    once.warn(
                            "login-time:" + item.value(),
                            "Login-Time {}: not understood, the user is rejected",
                            item.value());
                    StoreAccessHandler.because(context, "Login-Time not understood: ", item.value());
                    return AccessHandler.REJECT;
                }
                long left = window.secondsLeft(local);
                if (left < 0) {
                    StoreAccessHandler.because(context, "outside Login-Time ", item.value());
                    return AccessHandler.REJECT;
                }
                cap = Math.min(cap, Math.max(1, left));
            } else {
                for (UsageCounters.Counter counter : counters.counters()) {
                    if (!counter.check().equalsIgnoreCase(name)) {
                        continue;
                    }
                    long limit;
                    try {
                        limit = Long.parseLong(item.value().trim());
                    } catch (NumberFormatException e) {
                        once.warn(
                                "counter:" + name, "{}: {} is not a number, the user is rejected", name, item.value());
                        StoreAccessHandler.because(context, name + " is not a number: ", item.value());
                        return AccessHandler.REJECT;
                    }
                    long used;
                    try {
                        used = counters.usage(counter, user, UsageCounters.periodStart(counter.reset(), local));
                    } catch (Exception e) {
                        once.warn(
                                "counter-unavailable:" + counter.name(),
                                "usage counter {} unavailable, requests are not answered: {}",
                                counter.name(),
                                e.toString());
                        StoreAccessHandler.because(context, "usage counter unavailable: ", counter.name());
                        return AccessHandler.DROP;
                    }
                    StoreAccessHandler.note(context, counter.name() + ": used " + used + " of ", item.value());
                    if (used >= limit) {
                        StoreAccessHandler.because(context, "usage limit reached: ", counter.name());
                        return AccessHandler.REJECT;
                    }
                    if (counter.kind() == UsageCounters.Kind.TIME) {
                        cap = Math.min(cap, limit - used);
                        Instant end = UsageCounters.periodEnd(counter.reset(), local);
                        if (end != null) {
                            cap = Math.min(
                                    cap,
                                    Math.max(
                                            1,
                                            java.time.Duration.between(now, end).getSeconds()));
                        }
                    } else if (counter.reply() != null) {
                        replace(a.reply(), counter.reply(), Long.toString(limit - used));
                    }
                }
            }
        }
        if (cap != Long.MAX_VALUE) {
            long timeout = cap;
            for (AttributeItem r : a.reply()) {
                if (r.attribute().equalsIgnoreCase("Session-Timeout")) {
                    try {
                        timeout = Math.min(timeout, Long.parseLong(r.value().trim()));
                    } catch (NumberFormatException e) {
                        // a malformed value is replaced
                    }
                }
            }
            replace(a.reply(), "Session-Timeout", Long.toString(Math.min(timeout, 0xFFFFFFFFL)));
            StoreAccessHandler.note(
                    context, "Session-Timeout capped to ", Long.toString(Math.min(timeout, 0xFFFFFFFFL)));
        }
        return AccessHandler.ACCEPT;
    }

    static String simultaneousUse(List<AttributeItem> check) {
        for (AttributeItem item : check) {
            if (item.attribute().equalsIgnoreCase(StoreAccessHandler.SIMULTANEOUS_USE)) {
                return item.value();
            }
        }
        return null;
    }

    /**
     * Applies {@code Simultaneous-Use} after a successful authentication (ADR 0023): the cluster counts the user's
     * devices online and reserved. Over the limit → Reject; no answer from the cluster → no answer to the NAS; before
     * the cluster counts users (state version 6) the limit is ignored, as before.
     */
    int limit(AccessContext context, RadiusPacket request, String store, String value) {
        int maxDevices;
        try {
            maxDevices = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            maxDevices = -1;
        }
        if (maxDevices < 0 || maxDevices > 0xFFFF) {
            once.warn(
                    "simultaneous-use:" + store,
                    "store {}: Simultaneous-Use is not a number from 0 to 65535;" + " such users are rejected",
                    store);
            return AccessHandler.REJECT;
        }
        int at = request.findAttribute(USER_NAME);
        long user = UserKeys.user(request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
        int station = request.findAttribute(CALLING_STATION_ID);
        long device = station < 0
                ? 0
                : UserKeys.device(
                        request.buffer(), station + 2, (request.buffer().getByte(station + 1) & 0xFF) - 2);
        return switch (context.sessionLimits().reserve(user, device, maxDevices)) {
            case SessionLimits.GRANTED -> AccessHandler.ACCEPT;
            case SessionLimits.DENIED -> AccessHandler.REJECT;
            case SessionLimits.UNSUPPORTED -> {
                once.warn(
                        "simultaneous-use-unsupported",
                        "Simultaneous-Use is not applied until the cluster activates state version 6",
                        null);
                yield AccessHandler.ACCEPT;
            }
            default -> AccessHandler.DROP;
        };
    }

    /**
     * {@code Expire-After := <seconds>} (ADR 0060): the account ends that long after its first login, the start of
     * its first exported session (the first Accept, if none yet). The seconds left, {@code -1} to reject, {@code -2}
     * to leave the request unanswered (the database cannot be asked).
     */
    private long expireAfter(AccessContext context, String user, AttributeItem item, Instant now) {
        long seconds;
        try {
            seconds = Long.parseLong(item.value().trim());
        } catch (NumberFormatException e) {
            seconds = -1;
        }
        if (seconds <= 0) {
            once.warn(
                    "expire-after:" + item.value(), "Expire-After {}: not a number of seconds, rejected", item.value());
            StoreAccessHandler.because(context, "Expire-After not understood: ", item.value());
            return -1;
        }
        UsageCounters c = counters;
        if (c == null) {
            once.warn(
                    "expire-after-sql",
                    "{} needs auth.counter.sql.url to find the first login: rejected",
                    "Expire-After");
            StoreAccessHandler.because(context, "Expire-After without auth.counter.sql.url", "");
            return -1;
        }
        Instant first;
        try {
            first = c.firstLogin(user);
        } catch (Exception e) {
            once.warn(
                    "expire-after-unavailable",
                    "first logins unavailable, requests are not answered: {}",
                    e.toString());
            StoreAccessHandler.because(context, "first login unavailable", "");
            return -2;
        }
        Instant end = (first == null ? now : first).plusSeconds(seconds);
        if (!now.isBefore(end)) {
            StoreAccessHandler.because(context, "expired after the first login: ", end.toString());
            return -1;
        }
        return java.time.Duration.between(now, end).getSeconds();
    }

    static void replace(List<AttributeItem> reply, String attribute, String value) {
        reply.removeIf(r -> r.attribute().equalsIgnoreCase(attribute));
        reply.add(new AttributeItem(attribute, "=", value));
    }
}
