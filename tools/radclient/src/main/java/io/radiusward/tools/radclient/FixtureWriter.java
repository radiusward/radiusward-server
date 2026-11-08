/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.AttributeValues;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.DataType;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.agrona.DirectBuffer;

/**
 * {@code radclient decode --fixture}: turns a captured packet into the {@code attributes:} of a vendor fixture
 * ({@code radius-codec/src/test/resources/fixtures}, format in {@code docs/testing/strategy.md}).
 *
 * <p>The {@code packet:} line is left out on purpose: fixtures are re-signed with the test secret, so it is
 * written by {@code VendorFixtureTest -Dfixtures.update=true}. With {@code anonymise}, addresses, MAC addresses
 * and user names are replaced consistently (the same input always gets the same replacement), so the result
 * can be committed; it still has to be reviewed by hand (docs/testing/vendor-captures.md).
 */
final class FixtureWriter {

    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b");
    private static final Pattern MAC = Pattern.compile(
            "\\b[0-9A-Fa-f]{2}([:.-])[0-9A-Fa-f]{2}(\\1[0-9A-Fa-f]{2}){4}\\b|\\b[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}\\b");

    private final Dictionary dictionary;
    private final boolean anonymise;
    private final Map<String, String> addresses = new HashMap<>();
    private final Map<String, String> macs = new HashMap<>();
    private final Map<String, String> users = new HashMap<>();

    FixtureWriter(Dictionary dictionary, boolean anonymise) {
        this.dictionary = dictionary;
        this.anonymise = anonymise;
    }

    String write(RadiusPacket packet, String comment) {
        StringBuilder out = new StringBuilder();
        out.append("# ").append(comment).append('\n');
        out.append("# CAPTURED")
                .append(anonymise ? ", anonymised by radclient decode --fixture --anonymise; reviewed: TODO" : "")
                .append('\n');
        out.append("identifier: ").append(packet.identifier()).append('\n');
        out.append("attributes:\n");
        AttributeCursor cursor = new AttributeCursor(VendorFormats.from(dictionary)).wrap(packet);
        while (cursor.next()) {
            AttributeDef def = cursor.vendorId() == 0
                    ? dictionary.attribute(cursor.type())
                    : dictionary.vendorAttribute(cursor.vendorId(), cursor.type());
            if (def == null) {
                out.append("  # not in the dictionary: vendor ")
                        .append(cursor.vendorId())
                        .append(" type ")
                        .append(cursor.type())
                        .append(" = 0x")
                        .append(
                                anonymise
                                        ? "(removed)"
                                        : AttributeValues.hex(
                                                cursor.buffer(), cursor.valueOffset(), cursor.valueLength()))
                        .append('\n');
                continue;
            }
            String name = cursor.vendorId() == 0 ? def.name() : def.vendor().name() + "." + def.name();
            out.append("  ")
                    .append(name)
                    .append(": ")
                    .append(value(def, cursor.buffer(), cursor.valueOffset(), cursor.valueLength()))
                    .append('\n');
        }
        out.append("""
                # packet: is written by VendorFixtureTest with -Dfixtures.update=true (re-signed with the test secret)
                expect:
                  # TODO: the hot fields the extractor must produce, from the vendor documentation
                """);
        return out.toString();
    }

    /** In the syntax {@code VendorFixtureTest} encodes: names, decimals, dotted quads, raw strings, else 0x. */
    private String value(AttributeDef def, DirectBuffer buffer, int offset, int length) {
        switch (def.type()) {
            case UINT32, DATE -> {
                long v = AttributeValues.uint32(buffer, offset, length);
                if (v != AttributeValues.INVALID) {
                    String name = def.type() == DataType.UINT32 ? def.valueName(v) : null;
                    return name != null ? name : Long.toString(v);
                }
            }
            case IPV4_ADDR -> {
                long v = AttributeValues.ipv4(buffer, offset, length);
                if (v != AttributeValues.INVALID) {
                    String address = AttributeValues.ipv4String(v);
                    return anonymise ? address(address) : address;
                }
            }
            case STRING -> {
                String s = AttributeValues.string(buffer, offset, length);
                if (printable(buffer, offset, length) && !s.startsWith("0x") && s.equals(s.strip()) && !s.isEmpty()) {
                    return anonymise ? anonymiseString(def, s) : s;
                }
            }
            default -> {}
        }
        return "0x" + AttributeValues.hex(buffer, offset, length); // review by hand when anonymising
    }

    private String anonymiseString(AttributeDef def, String s) {
        String lower = def.name().toLowerCase(Locale.ROOT);
        if (lower.equals("user-name")) {
            int at = s.indexOf('@');
            String user = users.computeIfAbsent(at < 0 ? s : s.substring(0, at), k -> "user" + (users.size() + 1));
            return at < 0 ? user : user + "@example.net";
        }
        String result = replaceAll(
                MAC,
                s,
                m -> macs.computeIfAbsent(m.group().toLowerCase(Locale.ROOT), k -> mac(m.group(), macs.size() + 1)));
        result = replaceAll(IPV4, result, m -> address(m.group()));
        return result;
    }

    /** Documentation ranges (RFC 5737): 192.0.2.x, then 198.51.100.x, then 203.0.113.x. */
    private String address(String original) {
        return addresses.computeIfAbsent(original, k -> {
            int n = addresses.size() + 1;
            String[] nets = {"192.0.2.", "198.51.100.", "203.0.113."};
            return nets[Math.min((n - 1) / 254, 2)] + ((n - 1) % 254 + 1);
        });
    }

    /** A locally administered MAC address (02:...) in the original's notation. */
    private static String mac(String original, int n) {
        String digits = String.format("02000000%04x", n);
        StringBuilder out = new StringBuilder();
        int d = 0;
        for (char c : original.toCharArray()) {
            if (Character.digit(c, 16) >= 0) {
                char r = digits.charAt(d++);
                out.append(Character.isUpperCase(c) ? Character.toUpperCase(r) : r);
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String replaceAll(
            Pattern pattern, String s, java.util.function.Function<Matcher, String> replacement) {
        Matcher m = pattern.matcher(s);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(out, Matcher.quoteReplacement(replacement.apply(m)));
        }
        m.appendTail(out);
        return out.toString();
    }

    private static boolean printable(DirectBuffer buffer, int offset, int length) {
        for (int i = 0; i < length; i++) {
            int b = buffer.getByte(offset + i) & 0xFF;
            if (b < 0x20 || b == 0x7F) {
                return false;
            }
        }
        return true;
    }
}
