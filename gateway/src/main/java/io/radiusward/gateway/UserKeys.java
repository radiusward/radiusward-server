/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import org.agrona.DirectBuffer;

/**
 * Keys of users and devices for simultaneous use (ADR 0023), computed alike on the accounting path, the access path
 * and every gateway. Allocation-free; 0 means none.
 */
public final class UserKeys {

    private UserKeys() {}

    /** The User-Name, ASCII letters folded to lower case, hashed to 64 bits; 0 if empty. */
    public static long user(DirectBuffer buffer, int offset, int length) {
        if (length <= 0) {
            return 0;
        }
        long h = 0xcbf2_9ce4_8422_2325L;
        for (int i = 0; i < length; i++) {
            int c = buffer.getByte(offset + i) & 0xFF;
            if (c >= 'A' && c <= 'Z') {
                c += 'a' - 'A';
            }
            h = (h ^ c) * 0x0000_0100_0000_01B3L;
        }
        h = mix(h);
        return h == 0 ? 1 : h;
    }

    /**
     * The Calling-Station-Id: a MAC address in any notation ({@code AA-BB-CC-DD-EE-FF}, {@code aabb.ccdd.eeff},
     * {@code aabbccddeeff}) as its 48 bits, so all notations match; anything else hashed (ASCII case folded). 0 if
     * empty.
     */
    public static long device(DirectBuffer buffer, int offset, int length) {
        if (length <= 0) {
            return 0;
        }
        long mac = 0;
        int digits = 0;
        boolean macLike = true;
        for (int i = 0; i < length && macLike; i++) {
            int c = buffer.getByte(offset + i) & 0xFF;
            int v = Character.digit(c, 16);
            if (v >= 0 && c < 0x80) {
                mac = (mac << 4) | v;
                digits++;
            } else if (c != '-' && c != ':' && c != '.' && c != ' ') {
                macLike = false;
            }
        }
        if (macLike && digits == 12) {
            return mac | (1L << 48); // never 0, even for 00:00:00:00:00:00
        }
        return user(buffer, offset, length) | Long.MIN_VALUE; // apart from every MAC
    }

    private static long mix(long h) {
        h ^= h >>> 33;
        h *= 0xff51_afd7_ed55_8ccdL;
        h ^= h >>> 33;
        h *= 0xc4ce_b9fe_1a85_ec53L;
        return h ^ (h >>> 33);
    }
}
