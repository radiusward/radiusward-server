/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.agrona.collections.Int2ObjectHashMap;

/**
 * The type data of EAP-SIM, EAP-AKA and EAP-AKA′ messages (RFC 4186 §8.1, RFC 4187 §8.1, ADR 0061): a subtype, two
 * reserved bytes and attributes, each a type, a length in 4-byte units and a value. Building and reading; a message
 * that does not parse yields {@code null}, never an exception.
 */
final class SimMessage {

    static final int AT_RAND = 1;
    static final int AT_AUTN = 2;
    static final int AT_RES = 3;
    static final int AT_AUTS = 4;
    static final int AT_PADDING = 6;
    static final int AT_NONCE_MT = 7;
    static final int AT_PERMANENT_ID_REQ = 10;
    static final int AT_MAC = 11;
    static final int AT_NOTIFICATION = 12;
    static final int AT_ANY_ID_REQ = 13;
    static final int AT_IDENTITY = 14;
    static final int AT_VERSION_LIST = 15;
    static final int AT_SELECTED_VERSION = 16;
    static final int AT_FULLAUTH_ID_REQ = 17;
    static final int AT_COUNTER = 19;
    static final int AT_COUNTER_TOO_SMALL = 20;
    static final int AT_NONCE_S = 21;
    static final int AT_CLIENT_ERROR_CODE = 22;
    static final int AT_KDF_INPUT = 23;
    static final int AT_KDF = 24;
    static final int AT_IV = 129;
    static final int AT_ENCR_DATA = 130;
    static final int AT_NEXT_PSEUDONYM = 132;
    static final int AT_NEXT_REAUTH_ID = 133;
    static final int AT_CHECKCODE = 134;
    static final int AT_RESULT_IND = 135;

    private final int subtype;

    private final Int2ObjectHashMap<byte[]> attributes;
    private final int macOffset;

    private SimMessage(int subtype, Int2ObjectHashMap<byte[]> attributes, int macOffset) {
        this.subtype = subtype;
        this.attributes = attributes;
        this.macOffset = macOffset;
    }

    int subtype() {
        return subtype;
    }

    /** The value of an attribute (after its type and length bytes), or {@code null}. */
    byte[] get(int type) {
        return attributes.get(type);
    }

    boolean has(int type) {
        return attributes.containsKey(type);
    }

    /** Offset of AT_MAC's MAC within the type data, -1 if absent. */
    int macOffset() {
        return macOffset;
    }

    /**
     * Parses type data; {@code null} if an attribute is truncated, has length 0, or appears twice. Unknown attributes
     * below 128 are not skippable (RFC 4187 §8.1): a message with one is refused; 128 and above are skipped.
     */
    static SimMessage parse(byte[] data) {
        if (data.length < 3) {
            return null;
        }
        Int2ObjectHashMap<byte[]> attributes = new Int2ObjectHashMap<>();
        int mac = -1;
        int at = 3;
        while (at < data.length) {
            if (at + 2 > data.length) {
                return null;
            }
            int type = data[at] & 0xFF;
            int length = (data[at + 1] & 0xFF) * 4;
            if (length == 0 || at + length > data.length || attributes.containsKey(type)) {
                return null;
            }
            if (!known(type) && type < 128) {
                return null;
            }
            attributes.put(type, Arrays.copyOfRange(data, at + 2, at + length));
            if (type == AT_MAC) {
                mac = at + 4;
            }
            at += length;
        }
        return new SimMessage(data[0] & 0xFF, attributes, mac);
    }

    private static boolean known(int type) {
        return switch (type) {
            case AT_RAND,
                    AT_AUTN,
                    AT_RES,
                    AT_AUTS,
                    AT_PADDING,
                    AT_NONCE_MT,
                    AT_PERMANENT_ID_REQ,
                    AT_MAC,
                    AT_NOTIFICATION,
                    AT_ANY_ID_REQ,
                    AT_IDENTITY,
                    AT_VERSION_LIST,
                    AT_SELECTED_VERSION,
                    AT_FULLAUTH_ID_REQ,
                    AT_COUNTER,
                    AT_COUNTER_TOO_SMALL,
                    AT_NONCE_S,
                    AT_CLIENT_ERROR_CODE,
                    AT_KDF_INPUT,
                    AT_KDF,
                    AT_IV,
                    AT_ENCR_DATA,
                    AT_NEXT_PSEUDONYM,
                    AT_NEXT_REAUTH_ID,
                    AT_CHECKCODE,
                    AT_RESULT_IND -> true;
            default -> false;
        };
    }

    /** The value of a variable-length attribute that starts with its actual length in bytes (AT_IDENTITY, …). */
    static byte[] lengthPrefixed(byte[] value) {
        if (value == null || value.length < 2) {
            return null;
        }
        int n = ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
        return n > value.length - 2 ? null : Arrays.copyOfRange(value, 2, 2 + n);
    }

    /** Builds type data: a subtype, then attributes in order. */
    static final class Builder {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private int macOffset = -1;

        Builder(int subtype) {
            out.write(subtype);
            out.write(0);
            out.write(0);
        }

        /** An attribute whose value (after type and length) is {@code value}, padded with zeros to 4 bytes. */
        Builder add(int type, byte[] value) {
            int length = (2 + value.length + 3) / 4 * 4;
            out.write(type);
            out.write(length / 4);
            out.writeBytes(value);
            out.writeBytes(new byte[length - 2 - value.length]);
            return this;
        }

        /** Two reserved bytes, then {@code value}: AT_RAND (several RANDs), AT_AUTN, AT_NONCE_*, AT_IV. */
        Builder reserved(int type, byte[] value) {
            byte[] v = new byte[2 + value.length];
            System.arraycopy(value, 0, v, 2, value.length);
            return add(type, v);
        }

        /** Its actual length in bytes, then {@code value}: AT_IDENTITY, AT_KDF_INPUT, AT_NEXT_PSEUDONYM, … */
        Builder lengthPrefixed(int type, byte[] value) {
            byte[] v = new byte[2 + value.length];
            v[0] = (byte) (value.length >>> 8);
            v[1] = (byte) value.length;
            System.arraycopy(value, 0, v, 2, value.length);
            return add(type, v);
        }

        /** A 16-bit value: AT_KDF, AT_NOTIFICATION, AT_COUNTER, AT_SELECTED_VERSION, … */
        Builder uint16(int type, int value) {
            return add(type, new byte[] {(byte) (value >>> 8), (byte) value});
        }

        /** AT_MAC with zeros, its position remembered for {@link #sign}. */
        Builder mac() {
            macOffset = out.size() + 4;
            return add(AT_MAC, new byte[18]);
        }

        byte[] build() {
            return out.toByteArray();
        }

        int macOffset() {
            return macOffset;
        }
    }

    /**
     * The whole EAP packet over which AT_MAC is computed: code, identifier, length, type, then the type data with the
     * MAC zeroed (RFC 4186 §10.14).
     */
    static byte[] packet(int code, int identifier, int type, byte[] data, int macOffset) {
        byte[] p = new byte[5 + data.length];
        p[0] = (byte) code;
        p[1] = (byte) identifier;
        p[2] = (byte) (p.length >>> 8);
        p[3] = (byte) p.length;
        p[4] = (byte) type;
        System.arraycopy(data, 0, p, 5, data.length);
        if (macOffset >= 0) {
            Arrays.fill(p, 5 + macOffset, 5 + macOffset + 16, (byte) 0);
        }
        return p;
    }
}
