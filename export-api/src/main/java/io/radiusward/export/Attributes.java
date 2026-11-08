/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.AttributeValues;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.codec.attributes.AccountingAttributeExtractor;
import io.radiusward.radius.codec.attributes.AccountingFields;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Decodes the attribute section of an exported event with the dictionaries in use (ADR 0018):
 *
 * <ul>
 *   <li>{@link #common} — the values sinks keep in typed columns;
 *   <li>{@link #json} — the canonical JSON every sink uses for the remaining attributes. Every attribute maps to
 *       an <b>array</b> (repeated attributes keep all values in order; JSON objects cannot hold duplicate keys),
 *       integers with a dictionary name use it, IPv4 addresses are dotted quads, printable strings are strings,
 *       everything else is {@code {"base64": "..."}}; attributes missing from the dictionary are named
 *       {@code Attr-<type>} or {@code Vendor-<id>-Attr-<type>}. Strings never contain U+0000.
 * </ul>
 *
 * <p>Not thread-safe; one instance per sink thread.
 */
public final class Attributes {

    /** Version of the {@link #json} format, stored by sinks next to the JSON. */
    public static final int JSON_FORMAT = 1;

    /** Names of the attributes {@link #common} covers; sinks usually leave them out of the JSON. */
    public static final Set<String> COMMON = Set.of(
            "Acct-Status-Type",
            "Acct-Session-Id",
            "Acct-Session-Time",
            "Acct-Input-Octets",
            "Acct-Output-Octets",
            "Acct-Input-Gigawords",
            "Acct-Output-Gigawords",
            "Event-Timestamp",
            "User-Name",
            "Framed-IP-Address",
            "NAS-IP-Address",
            "NAS-Identifier",
            "Calling-Station-Id",
            "Called-Station-Id",
            "Acct-Terminate-Cause");

    /** Values kept in typed columns; {@code null} when the attribute is absent. */
    public record Common(
            String userName,
            String framedIp,
            String nasIp,
            String nasIdentifier,
            String callingStationId,
            String calledStationId,
            Integer terminateCause) {}

    private final Dictionary dictionary;
    private final VendorFormats formats;
    private final AttributeCursor cursor;
    private final AccountingAttributeExtractor extractor;
    private final AccountingFields fields = new AccountingFields();
    private final RadiusPacket packet = new RadiusPacket();
    private final UnsafeBuffer packetBuffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final UnsafeBuffer raw = new UnsafeBuffer(new byte[0]);

    public Attributes(Dictionary dictionary) {
        this.dictionary = dictionary;
        this.formats = VendorFormats.from(dictionary);
        this.cursor = new AttributeCursor(formats);
        this.extractor = new AccountingAttributeExtractor(formats);
    }

    public Common common(byte[] attributes) {
        if (attributes == null || attributes.length == 0) {
            return new Common(null, null, null, null, null, null, null);
        }
        int length = RadiusPacket.HEADER_LENGTH + attributes.length;
        if (length > RadiusPacket.MAX_LENGTH) {
            return new Common(null, null, null, null, null, null, null);
        }
        packetBuffer.putByte(RadiusPacket.CODE_OFFSET, (byte) 4);
        packetBuffer.putByte(RadiusPacket.IDENTIFIER_OFFSET, (byte) 0);
        packetBuffer.putShort(RadiusPacket.LENGTH_OFFSET, (short) length, java.nio.ByteOrder.BIG_ENDIAN);
        packetBuffer.putBytes(RadiusPacket.HEADER_LENGTH, attributes);
        if (packet.wrap(packetBuffer, 0, length) != io.radiusward.radius.codec.DecodeStatus.OK) {
            return new Common(null, null, null, null, null, null, null);
        }
        extractor.extract(packet, fields);
        return new Common(
                string(AccountingFields.USER_NAME, fields.userNameOffset(), fields.userNameLength()),
                fields.has(AccountingFields.FRAMED_IP_ADDRESS)
                        ? AttributeValues.ipv4String(fields.framedIpAddress())
                        : null,
                fields.has(AccountingFields.NAS_IP_ADDRESS) ? AttributeValues.ipv4String(fields.nasIpAddress()) : null,
                string(AccountingFields.NAS_IDENTIFIER, fields.nasIdentifierOffset(), fields.nasIdentifierLength()),
                string(
                        AccountingFields.CALLING_STATION_ID,
                        fields.callingStationIdOffset(),
                        fields.callingStationIdLength()),
                string(
                        AccountingFields.CALLED_STATION_ID,
                        fields.calledStationIdOffset(),
                        fields.calledStationIdLength()),
                fields.has(AccountingFields.TERMINATE_CAUSE) ? (int) fields.terminateCause() : null);
    }

    private String string(int field, int offset, int length) {
        if (!fields.has(field)) {
            return null;
        }
        String s = AttributeValues.string(fields.buffer(), offset, length);
        return s.indexOf('\0') >= 0 ? s.replace("\0", "") : s;
    }

    /** Canonical JSON of all attributes except {@code exclude} (by dictionary name); {@code null} if none remain. */
    public String json(byte[] attributes, Set<String> exclude) {
        if (attributes == null || attributes.length == 0) {
            return null;
        }
        raw.wrap(attributes);
        cursor.wrap(raw, 0, attributes.length);
        Map<String, List<String>> values = new LinkedHashMap<>();
        while (cursor.next()) {
            AttributeDef def = cursor.vendorId() == 0
                    ? dictionary.attribute(cursor.type())
                    : dictionary.vendorAttribute(cursor.vendorId(), cursor.type());
            String name = def != null
                    ? (cursor.vendorId() == 0 ? def.name() : def.vendor().name() + "." + def.name())
                    : (cursor.vendorId() == 0
                            ? "Attr-" + cursor.type()
                            : "Vendor-" + cursor.vendorId() + "-Attr-" + cursor.type());
            if (exclude.contains(name)) {
                continue;
            }
            values.computeIfAbsent(name, k -> new java.util.ArrayList<>())
                    .add(value(def, cursor.valueOffset(), cursor.valueLength()));
        }
        if (values.isEmpty()) {
            return null;
        }
        StringBuilder out = new StringBuilder(64 + attributes.length * 2);
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, List<String>> e : values.entrySet()) {
            if (!first) {
                out.append(',');
            }
            first = false;
            quote(out, e.getKey());
            out.append(":[");
            for (int i = 0; i < e.getValue().size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(e.getValue().get(i));
            }
            out.append(']');
        }
        return out.append('}').toString();
    }

    /** One value as a JSON fragment. */
    private String value(AttributeDef def, int offset, int length) {
        if (def != null) {
            switch (def.type()) {
                case UINT8, UINT16, UINT32, BOOL, DATE, TIME_DELTA -> {
                    long v = switch (length) {
                        case 1 -> AttributeValues.uint8(raw, offset, length);
                        case 2 -> AttributeValues.uint16(raw, offset, length);
                        case 4 -> AttributeValues.uint32(raw, offset, length);
                        default -> AttributeValues.INVALID;
                    };
                    if (v != AttributeValues.INVALID) {
                        String name = def.valueName(v);
                        return name != null ? quoted(name) : Long.toString(v);
                    }
                }
                case UINT64 -> {
                    if (length == 8) {
                        return Long.toUnsignedString(AttributeValues.uint64(raw, offset, length));
                    }
                }
                case IPV4_ADDR -> {
                    long v = AttributeValues.ipv4(raw, offset, length);
                    if (v != AttributeValues.INVALID) {
                        return quoted(AttributeValues.ipv4String(v));
                    }
                }
                case STRING -> {
                    if (printable(offset, length)) {
                        return quoted(AttributeValues.string(raw, offset, length));
                    }
                }
                default -> {}
            }
        }
        byte[] bytes = new byte[length];
        raw.getBytes(offset, bytes);
        return "{\"base64\":\"" + Base64.getEncoder().encodeToString(bytes) + "\"}";
    }

    private boolean printable(int offset, int length) {
        for (int i = 0; i < length; i++) {
            int b = raw.getByte(offset + i) & 0xFF;
            if (b < 0x20 || b == 0x7F) {
                return false;
            }
        }
        return true;
    }

    private static String quoted(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2);
        quote(out, s);
        return out.toString();
    }

    private static void quote(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
