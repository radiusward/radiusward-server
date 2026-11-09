/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import io.radiusward.radius.dictionary.AttributeDef;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.agrona.DirectBuffer;

/**
 * Attribute values as text, by their dictionary type: what operators write ({@code Session-Timeout = 3600},
 * {@code Service-Type = Framed-User}, {@code Framed-IP-Address = 10.0.0.1}, {@code Class = 0x0102}) to bytes and
 * back. Allocates; for configuration, stores and tools, not the hot path.
 */
public final class AttributeText {

    private AttributeText() {}

    /**
     * The value bytes of {@code text} for {@code def}: integers as numbers or the dictionary's {@code VALUE} names,
     * addresses as IP literals (never DNS), strings as UTF-8, anything as {@code 0x…} hex.
     *
     * @throws IllegalArgumentException if the text does not fit the type
     */
    public static byte[] encode(AttributeDef def, String text) {
        if (text.startsWith("0x")) {
            return HexFormat.of().parseHex(text.substring(2));
        }
        return switch (def.type()) {
            case UINT8, BOOL -> bytes(number(def, text), 1);
            case UINT16 -> bytes(number(def, text), 2);
            case UINT32, DATE, TIME_DELTA, INT32 -> bytes(number(def, text), 4);
            case UINT64, INT64 -> bytes(number(def, text), 8);
            case IPV4_ADDR -> address(def, text, 4);
            case IPV6_ADDR -> address(def, text, 16);
            case STRING, OCTETS -> text.getBytes(StandardCharsets.UTF_8);
            default ->
                throw new IllegalArgumentException(
                        def.path() + ": type " + def.type().dictionaryName() + " needs a 0x... hex value");
        };
    }

    /** The value as text, the inverse of {@link #encode} (unknown integer values as numbers, octets as 0x hex). */
    public static String decode(AttributeDef def, DirectBuffer buffer, int offset, int length) {
        return switch (def.type()) {
            case UINT8, BOOL, UINT16, UINT32, DATE, TIME_DELTA, INT32, UINT64, INT64 -> {
                long value = 0;
                for (int i = 0; i < length; i++) {
                    value = (value << 8) | (buffer.getByte(offset + i) & 0xFF);
                }
                String name = def.valueName(value);
                yield name != null ? name : Long.toString(value);
            }
            case IPV4_ADDR -> {
                if (length != 4) {
                    yield hex(buffer, offset, length);
                }
                yield (buffer.getByte(offset) & 0xFF) + "." + (buffer.getByte(offset + 1) & 0xFF) + "."
                        + (buffer.getByte(offset + 2) & 0xFF) + "." + (buffer.getByte(offset + 3) & 0xFF);
            }
            case STRING -> buffer.getStringWithoutLengthUtf8(offset, length);
            default -> hex(buffer, offset, length);
        };
    }

    private static String hex(DirectBuffer buffer, int offset, int length) {
        byte[] bytes = new byte[length];
        buffer.getBytes(offset, bytes);
        return "0x" + HexFormat.of().formatHex(bytes);
    }

    private static long number(AttributeDef def, String text) {
        Long named = def.value(text);
        if (named != null) {
            return named;
        }
        try {
            return Long.decode(text);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(def.path() + ": not a number or known value: " + text);
        }
    }

    private static byte[] bytes(long value, int size) {
        byte[] out = new byte[size];
        for (int i = size - 1; i >= 0; i--) {
            out[i] = (byte) value;
            value >>= 8;
        }
        return out;
    }

    private static byte[] address(AttributeDef def, String text, int size) {
        boolean literal = size == 4
                ? text.matches("\\d{1,3}(\\.\\d{1,3}){3}")
                : text.matches("[0-9A-Fa-f:.]+") && text.contains(":");
        if (!literal) {
            throw new IllegalArgumentException(
                    def.path() + ": expected an IPv" + (size == 4 ? 4 : 6) + " address literal: " + text);
        }
        try {
            InetAddress address = InetAddress.getByName(text); // a literal: no DNS look-up
            byte[] raw = address.getAddress();
            if (raw.length != size || (size == 16 && !(address instanceof Inet6Address))) {
                throw new IllegalArgumentException(
                        def.path() + ": expected an IPv" + (size == 4 ? 4 : 6) + " address: " + text);
            }
            return raw;
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(def.path() + ": invalid address " + text);
        }
    }
}
