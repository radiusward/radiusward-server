/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

/** TEAP's TLVs (RFC 7170 §4.2): their types, the Mandatory bit, the Result values, and the encoding. */
public final class TeapTlv {

    public static final int VERSION = 1;
    public static final int AUTHORITY_ID = 1;
    public static final int IDENTITY_TYPE = 2;
    public static final int RESULT = 3;
    public static final int NAK = 4;
    public static final int ERROR = 5;
    public static final int EAP_PAYLOAD = 9;
    public static final int INTERMEDIATE_RESULT = 10;
    public static final int CRYPTO_BINDING = 12;
    public static final int BASIC_PASSWORD_AUTH_REQ = 13;
    public static final int BASIC_PASSWORD_AUTH_RESP = 14;
    /** The M bit of the type: the receiver must understand the TLV. */
    public static final int MANDATORY = 0x8000;

    public static final int SUCCESS = 1;
    public static final int FAILURE = 2;
    /** The Crypto-Binding TLV: type and length, reserved, version, received version, sub-type, nonce, two MACs. */
    public static final int BINDING_LENGTH = 4 + 4 + 32 + 20 + 20;
    /** Where the MSK Compound MAC starts in the Crypto-Binding TLV. */
    public static final int MSK_MAC_AT = 4 + 4 + 32 + 20;

    private TeapTlv() {}

    /** A TLV: the type (with the M bit if mandatory), the value's length, the value. */
    public static byte[] encode(int type, byte[] value) {
        byte[] t = new byte[4 + value.length];
        t[0] = (byte) (type >>> 8);
        t[1] = (byte) type;
        t[2] = (byte) (value.length >>> 8);
        t[3] = (byte) value.length;
        System.arraycopy(value, 0, t, 4, value.length);
        return t;
    }
}
