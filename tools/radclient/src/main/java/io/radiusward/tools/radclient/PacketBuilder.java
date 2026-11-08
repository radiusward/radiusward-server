/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.VendorDef;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.agrona.concurrent.UnsafeBuffer;

/** Builds and signs Accounting-Requests from {@code Name=Value} pairs using the dictionary. */
final class PacketBuilder {

    private final Dictionary dictionary;
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private int messageAuthenticator = -1;

    PacketBuilder(Dictionary dictionary, int identifier) {
        this.dictionary = dictionary;
        encoder.wrap(buffer, 0).header(RadiusCode.ACCOUNTING_REQUEST, identifier);
    }

    /** Adds {@code Name=Value}; the name may be a path such as {@code Cisco.AVPair}. */
    PacketBuilder add(String assignment) {
        int eq = assignment.indexOf('=');
        if (eq <= 0) {
            throw new UsageException("attribute must be Name=Value: " + assignment);
        }
        return add(
                assignment.substring(0, eq).trim(), assignment.substring(eq + 1).trim());
    }

    PacketBuilder add(String name, String value) {
        AttributeDef def = dictionary.find(name);
        if (def == null) {
            throw new UsageException("unknown attribute " + name);
        }
        byte[] bytes = encode(def, value);
        if (def.vendorId() != 0) {
            VendorDef vendor = def.vendor();
            if (!vendor.isStandardFormat()
                    || !def.parent().type().equals(io.radiusward.radius.dictionary.DataType.VENDOR)) {
                throw new UsageException(def.path() + ": only standard-format vendor attributes are supported");
            }
            encoder.vendorAttribute(def.vendorId(), def.number(), bytes);
        } else if (def.isTopLevel()) {
            encoder.attribute(def.number(), bytes);
        } else {
            throw new UsageException(def.path() + ": nested attributes are not supported");
        }
        return this;
    }

    PacketBuilder messageAuthenticator() {
        messageAuthenticator = encoder.messageAuthenticator();
        return this;
    }

    /** Finishes and signs the request. */
    byte[] build(byte[] secret) {
        int length = encoder.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, messageAuthenticator, secret);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    static byte[] encode(AttributeDef def, String text) {
        if (text.startsWith("0x")) {
            return HexFormat.of().parseHex(text.substring(2));
        }
        return switch (def.type()) {
            case UINT8, BOOL -> bytes(number(def, text), 1);
            case UINT16 -> bytes(number(def, text), 2);
            case UINT32, DATE, TIME_DELTA, INT32 -> bytes(number(def, text), 4);
            case UINT64, INT64 -> bytes(number(def, text), 8);
            case IPV4_ADDR -> address(text, 4);
            case IPV6_ADDR -> address(text, 16);
            case STRING -> text.getBytes(StandardCharsets.UTF_8);
            case OCTETS -> text.getBytes(StandardCharsets.UTF_8);
            default ->
                throw new UsageException(
                        def.path() + ": type " + def.type().dictionaryName() + " needs a 0x... hex value");
        };
    }

    private static long number(AttributeDef def, String text) {
        Long named = def.value(text);
        if (named != null) {
            return named;
        }
        try {
            return Long.decode(text);
        } catch (NumberFormatException e) {
            throw new UsageException(def.path() + ": not a number or known value: " + text);
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

    private static byte[] address(String text, int size) {
        try {
            InetAddress address = InetAddress.getByName(text);
            byte[] raw = address.getAddress();
            if (raw.length != size || (size == 16 && !(address instanceof Inet6Address))) {
                throw new UsageException("expected an IPv" + (size == 4 ? 4 : 6) + " address: " + text);
            }
            return raw;
        } catch (UnknownHostException e) {
            throw new UsageException("invalid address " + text);
        }
    }
}
