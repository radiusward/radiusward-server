/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

/**
 * A vendor declared with {@code VENDOR name id [format=t,l[,c]]}.
 *
 * @param name vendor name
 * @param id IANA private enterprise number
 * @param typeLength size of the vendor attribute type field in bytes (1, 2 or 4)
 * @param lengthLength size of the vendor attribute length field in bytes (0, 1 or 2)
 * @param continuation whether the vendor uses a continuation byte ({@code format=1,1,c})
 */
public record VendorDef(String name, int id, int typeLength, int lengthLength, boolean continuation) {

    /** Format used when a vendor declares none: one byte type, one byte length. */
    public static final int DEFAULT_TYPE_LENGTH = 1;

    public static final int DEFAULT_LENGTH_LENGTH = 1;

    public VendorDef {
        if (typeLength != 1 && typeLength != 2 && typeLength != 4) {
            throw new IllegalArgumentException("invalid vendor type length " + typeLength + " for " + name);
        }
        if (lengthLength < 0 || lengthLength > 2) {
            throw new IllegalArgumentException("invalid vendor length length " + lengthLength + " for " + name);
        }
    }

    /** Whether this vendor uses the standard RFC 2865 VSA layout (one byte type, one byte length). */
    public boolean isStandardFormat() {
        return typeLength == DEFAULT_TYPE_LENGTH && lengthLength == DEFAULT_LENGTH_LENGTH && !continuation;
    }
}
