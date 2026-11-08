/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.VendorDef;

/**
 * Supplies the sub-attribute layout of a vendor's VSAs as a packed int, so the cursor can look it up
 * without allocating. Use {@link #pack(int, int, boolean)} to build values.
 */
@FunctionalInterface
public interface VendorFormats {

    /** RFC 2865 recommended layout: one byte type, one byte length, no continuation. */
    int STANDARD = pack(1, 1, false);

    /** Every vendor uses the standard layout. */
    VendorFormats ALL_STANDARD = vendorId -> STANDARD;

    /** Packed format of the vendor's VSAs. */
    int format(int vendorId);

    /** Formats declared in the dictionary; unknown vendors use the standard layout. */
    static VendorFormats from(Dictionary dictionary) {
        return vendorId -> {
            VendorDef vendor = dictionary.vendor(vendorId);
            return vendor == null ? STANDARD : pack(vendor.typeLength(), vendor.lengthLength(), vendor.continuation());
        };
    }

    static int pack(int typeLength, int lengthLength, boolean continuation) {
        return typeLength | (lengthLength << 4) | (continuation ? 1 << 8 : 0);
    }

    static int typeLength(int format) {
        return format & 0xF;
    }

    static int lengthLength(int format) {
        return (format >> 4) & 0xF;
    }

    static boolean continuation(int format) {
        return (format & (1 << 8)) != 0;
    }
}
