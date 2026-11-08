/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static java.nio.ByteOrder.BIG_ENDIAN;

import java.nio.charset.StandardCharsets;
import org.agrona.DirectBuffer;

/**
 * Readers for attribute values. Numeric readers return {@link #INVALID} when the value has the wrong
 * length instead of throwing, so the hot path stays allocation-free. Methods returning objects
 * ({@link #string}, {@link #hex}, {@link #ipv4String}) allocate and are meant for tooling and logs.
 */
public final class AttributeValues {

    /** Returned by the unsigned readers for a value of the wrong length. */
    public static final long INVALID = -1L;

    private AttributeValues() {}

    /** Unsigned 8 bit value, or {@link #INVALID}. */
    public static long uint8(DirectBuffer buffer, int offset, int length) {
        return length == 1 ? buffer.getByte(offset) & 0xFFL : INVALID;
    }

    /** Unsigned 16 bit value, or {@link #INVALID}. */
    public static long uint16(DirectBuffer buffer, int offset, int length) {
        return length == 2 ? buffer.getShort(offset, BIG_ENDIAN) & 0xFFFFL : INVALID;
    }

    /** Unsigned 32 bit value ({@code integer}, {@code date}), or {@link #INVALID}. */
    public static long uint32(DirectBuffer buffer, int offset, int length) {
        return length == 4 ? buffer.getInt(offset, BIG_ENDIAN) & 0xFFFF_FFFFL : INVALID;
    }

    /**
     * Unsigned 64 bit value ({@code integer64}). Values above {@link Long#MAX_VALUE} come back
     * negative; check {@code length == 8} instead of comparing with {@link #INVALID}.
     */
    public static long uint64(DirectBuffer buffer, int offset, int length) {
        return length == 8 ? buffer.getLong(offset, BIG_ENDIAN) : INVALID;
    }

    /** Signed 32 bit value; {@code Long.MIN_VALUE} for the wrong length. */
    public static long int32(DirectBuffer buffer, int offset, int length) {
        return length == 4 ? buffer.getInt(offset, BIG_ENDIAN) : Long.MIN_VALUE;
    }

    /** IPv4 address as an unsigned 32 bit value, or {@link #INVALID}. */
    public static long ipv4(DirectBuffer buffer, int offset, int length) {
        return uint32(buffer, offset, length);
    }

    /**
     * Combines a 32 bit octet counter with its RFC 2869 gigawords counter into a 64 bit count.
     * A missing gigawords attribute is passed as 0.
     */
    public static long octets64(long octets, long gigawords) {
        return ((gigawords & 0xFFFF_FFFFL) << 32) | (octets & 0xFFFF_FFFFL);
    }

    /** Whether the value equals {@code expected} byte by byte. Allocation-free. */
    public static boolean equals(DirectBuffer buffer, int offset, int length, byte[] expected) {
        if (length != expected.length) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            if (buffer.getByte(offset + i) != expected[i]) {
                return false;
            }
        }
        return true;
    }

    /** UTF-8 text value. Allocates. */
    public static String string(DirectBuffer buffer, int offset, int length) {
        byte[] bytes = new byte[length];
        buffer.getBytes(offset, bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** Dotted-quad IPv4 address. Allocates. */
    public static String ipv4String(long address) {
        return ((address >> 24) & 0xFF) + "." + ((address >> 16) & 0xFF) + "." + ((address >> 8) & 0xFF) + "."
                + (address & 0xFF);
    }

    /** Lower-case hex. Allocates. */
    public static String hex(DirectBuffer buffer, int offset, int length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            int b = buffer.getByte(offset + i) & 0xFF;
            sb.append(Character.forDigit(b >> 4, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
