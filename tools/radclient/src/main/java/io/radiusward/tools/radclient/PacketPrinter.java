/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.AttributeValues;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.time.Instant;
import org.agrona.DirectBuffer;

/** Renders a packet with dictionary names, one attribute per line. */
final class PacketPrinter {

    private final Dictionary dictionary;

    PacketPrinter(Dictionary dictionary) {
        this.dictionary = dictionary;
    }

    String print(RadiusPacket packet) {
        StringBuilder out = new StringBuilder();
        out.append(RadiusCode.name(packet.code()))
                .append(" id=")
                .append(packet.identifier())
                .append(" length=")
                .append(packet.length())
                .append('\n');
        AttributeCursor cursor = new AttributeCursor(VendorFormats.from(dictionary)).wrap(packet);
        while (cursor.next()) {
            AttributeDef def = cursor.vendorId() == 0
                    ? dictionary.attribute(cursor.type())
                    : dictionary.vendorAttribute(cursor.vendorId(), cursor.type());
            String name = def != null
                    ? (cursor.vendorId() == 0 ? def.name() : def.vendor().name() + "." + def.name())
                    : (cursor.vendorId() == 0
                            ? "Attr-" + cursor.type()
                            : "Vendor-" + cursor.vendorId() + "-Attr-" + cursor.type());
            out.append("  ")
                    .append(name)
                    .append(" = ")
                    .append(value(def, cursor.buffer(), cursor.valueOffset(), cursor.valueLength()))
                    .append('\n');
        }
        return out.toString();
    }

    static String value(AttributeDef def, DirectBuffer buffer, int offset, int length) {
        if (def != null) {
            switch (def.type()) {
                case UINT8, UINT16, UINT32, BOOL -> {
                    long v = switch (length) {
                        case 1 -> AttributeValues.uint8(buffer, offset, length);
                        case 2 -> AttributeValues.uint16(buffer, offset, length);
                        case 4 -> AttributeValues.uint32(buffer, offset, length);
                        default -> AttributeValues.INVALID;
                    };
                    if (v != AttributeValues.INVALID) {
                        String name = def.valueName(v);
                        return name != null ? name : Long.toString(v);
                    }
                }
                case UINT64 -> {
                    if (length == 8) {
                        return Long.toUnsignedString(AttributeValues.uint64(buffer, offset, length));
                    }
                }
                case DATE -> {
                    long v = AttributeValues.uint32(buffer, offset, length);
                    if (v != AttributeValues.INVALID) {
                        return Instant.ofEpochSecond(v) + " (" + v + ")";
                    }
                }
                case IPV4_ADDR -> {
                    long v = AttributeValues.ipv4(buffer, offset, length);
                    if (v != AttributeValues.INVALID) {
                        return AttributeValues.ipv4String(v);
                    }
                }
                case STRING -> {
                    if (printable(buffer, offset, length)) {
                        return '"' + AttributeValues.string(buffer, offset, length) + '"';
                    }
                }
                default -> {}
            }
        }
        return "0x" + AttributeValues.hex(buffer, offset, length);
    }

    private static boolean printable(DirectBuffer buffer, int offset, int length) {
        for (int i = 0; i < length; i++) {
            int b = buffer.getByte(offset + i) & 0xFF;
            if (b < 0x20 && b != '\t') {
                return false;
            }
        }
        return true;
    }
}
