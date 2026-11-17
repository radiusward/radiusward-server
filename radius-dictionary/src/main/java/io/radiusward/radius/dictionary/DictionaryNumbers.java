/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

/** Numbers and VALUE values as dictionary files write them. Pure functions. */
final class DictionaryNumbers {

    private DictionaryNumbers() {}

    /** Decimal, or hex with {@code 0x}; {@code null} if neither. */
    static Long parseLong(String token) {
        try {
            if (token.startsWith("0x") || token.startsWith("0X")) {
                return Long.parseUnsignedLong(token.substring(2), 16);
            }
            return Long.parseLong(token);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** A VALUE's value for an attribute of {@code type}: a number, or a dotted IPv4 address; {@code null} otherwise. */
    static Long parseValue(DataType type, String raw) {
        if (type.isInteger() || type == DataType.OCTETS || type == DataType.STRING) {
            Long number = parseLong(raw);
            if (number != null) {
                return number;
            }
        }
        if (type == DataType.IPV4_ADDR) {
            String[] octets = raw.split("\\.");
            if (octets.length == 4) {
                long v = 0;
                for (String o : octets) {
                    Long part = parseLong(o);
                    if (part == null || part < 0 || part > 255) {
                        return null;
                    }
                    v = (v << 8) | part;
                }
                return v;
            }
        }
        return null;
    }
}
