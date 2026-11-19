/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import java.io.ByteArrayOutputStream;

/** An EAP-TTLS AVP (RFC 5281 §10.1): code, flags, length, the vendor if any, the value padded to four bytes. */
public final class TtlsAvp {

    /** The vendor ID field is present. */
    public static final int FLAG_VENDOR = 0x80;
    /** The receiver must understand the AVP. */
    public static final int FLAG_MANDATORY = 0x40;

    private TtlsAvp() {}

    /** A mandatory AVP; {@code vendor} 0 for an IETF one (the RADIUS attribute number as its code). */
    public static byte[] encode(int code, int vendor, byte[] value) {
        int header = vendor != 0 ? 12 : 8;
        int length = header + value.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(code >>> 24);
        out.write(code >>> 16);
        out.write(code >>> 8);
        out.write(code);
        out.write((vendor != 0 ? FLAG_VENDOR : 0) | FLAG_MANDATORY);
        out.write(length >>> 16);
        out.write(length >>> 8);
        out.write(length);
        if (vendor != 0) {
            out.write(vendor >>> 24);
            out.write(vendor >>> 16);
            out.write(vendor >>> 8);
            out.write(vendor);
        }
        out.writeBytes(value);
        while (out.size() % 4 != 0) {
            out.write(0);
        }
        return out.toByteArray();
    }
}
