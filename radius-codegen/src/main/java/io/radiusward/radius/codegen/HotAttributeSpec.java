/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codegen;

import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.VendorDef;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The hot-attribute list: which attributes the generated extractor pulls out of a packet, and which
 * vendors get a constants class.
 *
 * <pre>
 * # comment
 * constants Cisco Juniper Mikrotik           # vendors that get a constants class (IETF always does)
 * ietf      Acct-Status-Type   statusType    # vendor ("ietf" or a vendor name), attribute, field
 * Cisco     AVPair             ciscoAvPair   repeat=8
 * </pre>
 */
public record HotAttributeSpec(List<VendorDef> constantVendors, List<Field> fields) {

    public static final String IETF = "ietf";

    private static final Pattern JAVA_IDENTIFIER = Pattern.compile("[a-z][A-Za-z0-9]*");
    private static final int MAX_FIELDS = 64; // presence bits live in one long

    /**
     * One extracted field.
     *
     * @param attribute dictionary definition (top-level or vendor attribute)
     * @param name Java field name
     * @param repeat maximum number of occurrences kept, {@code 1} for single-valued fields
     * @param line line of the spec file, for error messages
     */
    public record Field(AttributeDef attribute, String name, int repeat, int line) {}

    /** Parses and validates the spec against the dictionary. */
    public static HotAttributeSpec parse(List<String> lines, Dictionary dictionary) {
        Set<VendorDef> vendors = new LinkedHashSet<>();
        List<Field> fields = new ArrayList<>();
        Set<String> names = new HashSet<>();
        Set<AttributeDef> attributes = new HashSet<>();
        for (int i = 0; i < lines.size(); i++) {
            int lineNo = i + 1;
            String line = lines.get(i);
            int hash = line.indexOf('#');
            String content = (hash >= 0 ? line.substring(0, hash) : line).trim();
            if (content.isEmpty()) {
                continue;
            }
            String[] t = content.split("\\s+");
            if (t[0].equals("constants")) {
                for (int j = 1; j < t.length; j++) {
                    vendors.add(vendor(dictionary, t[j], lineNo));
                }
                continue;
            }
            if (t.length < 3 || t.length > 4) {
                throw error(lineNo, "expected '<vendor> <attribute> <field> [repeat=N]'");
            }
            AttributeDef attribute = attribute(dictionary, t[0], t[1], lineNo);
            String name = t[2];
            if (!JAVA_IDENTIFIER.matcher(name).matches()) {
                throw error(lineNo, "field name must be a lowerCamelCase Java identifier: " + name);
            }
            if (!names.add(name)) {
                throw error(lineNo, "duplicate field name " + name);
            }
            if (!attributes.add(attribute)) {
                throw error(lineNo, "attribute listed twice: " + attribute.path());
            }
            int repeat = 1;
            if (t.length == 4) {
                if (!t[3].startsWith("repeat=")) {
                    throw error(lineNo, "unknown option " + t[3]);
                }
                try {
                    repeat = Integer.parseInt(t[3].substring("repeat=".length()));
                } catch (NumberFormatException e) {
                    throw error(lineNo, "invalid repeat " + t[3]);
                }
                if (repeat < 2 || repeat > 64) {
                    throw error(lineNo, "repeat must be between 2 and 64");
                }
            }
            fields.add(new Field(attribute, name, repeat, lineNo));
        }
        if (fields.size() > MAX_FIELDS) {
            throw new IllegalArgumentException("at most " + MAX_FIELDS + " fields are supported, got " + fields.size());
        }
        for (Field field : fields) {
            VendorDef vendor = field.attribute().vendor();
            if (vendor != null && !vendors.contains(vendor)) {
                vendors.add(vendor);
            }
        }
        return new HotAttributeSpec(List.copyOf(vendors), List.copyOf(fields));
    }

    private static VendorDef vendor(Dictionary dictionary, String name, int line) {
        VendorDef vendor = dictionary.vendor(name);
        if (vendor == null) {
            throw error(line, "unknown vendor " + name);
        }
        return vendor;
    }

    private static AttributeDef attribute(Dictionary dictionary, String vendorName, String name, int line) {
        AttributeDef def;
        if (vendorName.equalsIgnoreCase(IETF)) {
            def = dictionary.find(name);
            if (def != null && !def.isTopLevel()) {
                throw error(line, name + " is not a top-level attribute: " + def.path());
            }
        } else {
            VendorDef vendor = vendor(dictionary, vendorName, line);
            AttributeDef vsa = dictionary.attribute(Dictionary.VENDOR_SPECIFIC);
            AttributeDef vendorNode = vsa == null ? null : vsa.child(vendor.id());
            def = vendorNode == null ? null : vendorNode.child(name);
            if (def != null && def.number() > 255) {
                throw error(line, name + " has a vendor type above 255, which the extractor does not support");
            }
        }
        if (def == null) {
            throw error(line, "unknown attribute " + vendorName + " " + name);
        }
        if (def.number() < 0 || def.internal()) {
            throw error(line, def.path() + " never appears on the wire");
        }
        return def;
    }

    private static IllegalArgumentException error(int line, String message) {
        return new IllegalArgumentException("hot-attributes line " + line + ": " + message);
    }
}
