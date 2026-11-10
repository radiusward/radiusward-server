/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;

/**
 * The attributes that name a session to its NAS (RFC 5176 §3, ADR 0036), taken from an accounting request's attribute
 * section in a fixed order of importance while they fit {@link SessionStore#IDENTITY_SIZE}: Acct-Session-Id,
 * User-Name, NAS-IP-Address, Framed-IP-Address, Calling-Station-Id, NAS-Identifier, NAS-IPv6-Address, NAS-Port,
 * NAS-Port-Id, Called-Station-Id. Kept as RADIUS attributes, ready to be copied into a Disconnect- or CoA-Request.
 * Pure and allocation-free: the same bytes on every member.
 */
public final class SessionIdentity {

    /** In order: what a NAS needs most to find the session comes first. */
    static final int[] TYPES = {44, 1, 4, 8, 31, 32, 95, 5, 87, 30};

    private SessionIdentity() {}

    /**
     * Writes the identifying attributes found in {@code attributes} to {@code out}; returns their length (0..63).
     * Malformed attribute sections yield what was found before the damage.
     */
    public static int extract(DirectBuffer attributes, int offset, int length, MutableDirectBuffer out, int outOffset) {
        int written = 0;
        int end = offset + length;
        for (int type : TYPES) {
            for (int at = offset; at + 2 <= end; ) {
                int t = attributes.getByte(at) & 0xFF;
                int l = attributes.getByte(at + 1) & 0xFF;
                if (l < 2 || at + l > end) {
                    break;
                }
                if (t == type) {
                    if (written + l < SessionStore.IDENTITY_SIZE) {
                        out.putBytes(outOffset + written, attributes, at, l);
                        written += l;
                    }
                    break; // the first one of each type
                }
                at += l;
            }
        }
        return written;
    }

    /** The value of attribute {@code type} in identifying attributes (e.g. the User-Name), or {@code null}. */
    public static String string(DirectBuffer identity, int offset, int length, int type) {
        for (int at = offset, end = offset + length; at + 2 <= end; ) {
            int l = identity.getByte(at + 1) & 0xFF;
            if (l < 2 || at + l > end) {
                return null;
            }
            if ((identity.getByte(at) & 0xFF) == type) {
                return identity.getStringWithoutLengthUtf8(at + 2, l - 2);
            }
            at += l;
        }
        return null;
    }
}
