/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.radius;

import static io.radiusward.radius.codec.attributes.Ietf.ACCT_DELAY_TIME;
import static io.radiusward.radius.codec.attributes.Ietf.MESSAGE_AUTHENTICATOR;
import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;

import io.radiusward.export.ExportEvent;
import io.radiusward.radius.codec.AttributeValues;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.function.LongSupplier;

/**
 * Which committed events go to the home servers and what the home servers get (ADR 0037): events whose User-Name
 * has one of the forwarded realms ({@code user@realm} or {@code REALM&#92;user}; {@code *} for any), with their attributes
 * as the NAS sent them, Acct-Delay-Time raised by the time since the commit, the realm stripped if configured, and no
 * Message-Authenticator (the request gets its own).
 */
final class ForwardedRequest {

    private final List<String> realms;
    private final boolean strip;
    private final LongSupplier clockMillis;

    /** @param realms lower case; {@code *} for every realm */
    ForwardedRequest(List<String> realms, boolean strip, LongSupplier clockMillis) {
        this.realms = List.copyOf(realms);
        this.strip = strip;
        this.clockMillis = clockMillis;
    }

    /** Whether the event's User-Name has one of the forwarded realms. */
    boolean forwarded(ExportEvent e) {
        String user = AttributeValues.string(e.rawAttributes(), USER_NAME);
        String realm = user == null ? "" : realm(user);
        return !realm.isEmpty() && (realms.contains("*") || realms.contains(realm.toLowerCase(Locale.ROOT)));
    }

    /** The request's attributes: the original ones, Acct-Delay-Time raised, the realm stripped if configured. */
    byte[] attributes(ExportEvent e) {
        byte[] raw = e.rawAttributes();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long delay = Math.max(0, (clockMillis.getAsLong() - e.commitTime()) / 1000);
        for (int at = 0; at + 2 <= raw.length; ) {
            int type = raw[at] & 0xFF;
            int l = raw[at + 1] & 0xFF;
            if (l < 2 || at + l > raw.length) {
                break;
            }
            if (type == ACCT_DELAY_TIME && l == 6) {
                delay += ((raw[at + 2] & 0xFFL) << 24)
                        | ((raw[at + 3] & 0xFF) << 16)
                        | ((raw[at + 4] & 0xFF) << 8)
                        | (raw[at + 5] & 0xFF);
            } else if (type == USER_NAME && strip) {
                byte[] b = bare(new String(raw, at + 2, l - 2, StandardCharsets.UTF_8))
                        .getBytes(StandardCharsets.UTF_8);
                out.write(USER_NAME);
                out.write(2 + b.length);
                out.writeBytes(b);
            } else if (type != MESSAGE_AUTHENTICATOR) {
                out.write(raw, at, l);
            }
            at += l;
        }
        long d = Math.min(delay, 0xFFFF_FFFFL);
        out.writeBytes(
                new byte[] {ACCT_DELAY_TIME, 6, (byte) (d >>> 24), (byte) (d >>> 16), (byte) (d >>> 8), (byte) d});
        return out.toByteArray();
    }

    /** The realm of {@code user@realm} or {@code REALM&#92;user}; empty without one. */
    static String realm(String user) {
        int at = user.lastIndexOf('@');
        int slash = user.indexOf('\\');
        return at >= 0 ? user.substring(at + 1) : slash > 0 ? user.substring(0, slash) : "";
    }

    /** The user without its realm. */
    static String bare(String user) {
        int at = user.lastIndexOf('@');
        int slash = user.indexOf('\\');
        return at >= 0 ? user.substring(0, at) : slash > 0 ? user.substring(slash + 1) : user;
    }
}
