/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.agrona.collections.Int2ObjectHashMap;
import org.agrona.collections.Long2ObjectHashMap;

/**
 * A loaded, immutable RADIUS dictionary.
 *
 * <p>Number-based lookups ({@link #attribute(int)}, {@link #vendorAttribute(int, int)},
 * {@link #vendor(int)}) are allocation-free and meant for the packet hot path. Name-based lookups
 * are for configuration and tooling.
 */
public final class Dictionary {

    /** RFC 2865 Vendor-Specific attribute number. */
    public static final int VENDOR_SPECIFIC = 26;

    private final AttributeDef root;
    private final Int2ObjectHashMap<VendorDef> vendorsById;
    private final Map<String, VendorDef> vendorsByName;
    private final Long2ObjectHashMap<AttributeDef> vsaIndex;
    private final Map<String, AttributeDef> flatNames;
    private final List<String> warnings;
    private final List<String> loadedFiles;
    private final int attributeCount;

    Dictionary(
            AttributeDef root,
            Int2ObjectHashMap<VendorDef> vendorsById,
            Map<String, VendorDef> vendorsByName,
            Long2ObjectHashMap<AttributeDef> vsaIndex,
            Map<String, AttributeDef> flatNames,
            List<String> warnings,
            List<String> loadedFiles,
            int attributeCount) {
        this.root = root;
        this.vendorsById = vendorsById;
        this.vendorsByName = vendorsByName;
        this.vsaIndex = vsaIndex;
        this.flatNames = flatNames;
        this.warnings = List.copyOf(warnings);
        this.loadedFiles = List.copyOf(loadedFiles);
        this.attributeCount = attributeCount;
    }

    /** The protocol root; its children are the top-level attributes. */
    public AttributeDef root() {
        return root;
    }

    /** Top-level attribute with the given type, or {@code null}. */
    public AttributeDef attribute(int type) {
        return root.child(type);
    }

    /** Attribute of a vendor inside RFC 2865 Vendor-Specific (26), or {@code null}. */
    public AttributeDef vendorAttribute(int vendorId, int type) {
        return vsaIndex.get(vsaKey(vendorId, type));
    }

    /** Vendor with the given id, or {@code null}. */
    public VendorDef vendor(int vendorId) {
        return vendorsById.get(vendorId);
    }

    /** Vendor with the given name (case-insensitive), or {@code null}. */
    public VendorDef vendor(String name) {
        return vendorsByName.get(AttributeDef.key(name));
    }

    public Collection<VendorDef> vendors() {
        return Collections.unmodifiableCollection(vendorsById.values());
    }

    /**
     * Finds an attribute by name.
     *
     * <p>Accepts a dotted path from the root ({@code Vendor-Specific.Cisco.AVPair}), a path that
     * starts at a root alias ({@code Cisco.AVPair}), or a plain v3-style name ({@code Cisco-AVPair},
     * {@code Acct-Status-Type}; a vendor attribute also by vendor name, a hyphen and its v4 name). Names are case-insensitive.
     *
     * @return the attribute, or {@code null}
     */
    public AttributeDef find(String name) {
        AttributeDef byPath = resolvePath(root, name);
        if (byPath != null) {
            return byPath;
        }
        AttributeDef flat = flatNames.get(AttributeDef.key(name));
        return flat != null ? flat : vendorPrefixed(name);
    }

    /**
     * A v3 name of a vendor attribute defined in v4 style: {@code Cisco-AVPair} for {@code Cisco.AVPair}. The longest
     * vendor name that prefixes {@code name} wins ({@code Alcatel-Lucent-...} before {@code Alcatel-...}).
     */
    private AttributeDef vendorPrefixed(String name) {
        AttributeDef best = null;
        int bestLength = 0;
        for (VendorDef vendor : vendorsById.values()) {
            String prefix = vendor.name();
            int length = prefix.length();
            if (length > bestLength
                    && name.length() > length + 1
                    && name.charAt(length) == '-'
                    && name.regionMatches(true, 0, prefix, 0, length)) {
                AttributeDef def = resolvePath(root, "Vendor-Specific." + prefix + "." + name.substring(length + 1));
                if (def != null) {
                    best = def;
                    bestLength = length;
                }
            }
        }
        return best;
    }

    /** Like {@link #find(String)} but fails with a clear message. */
    public AttributeDef require(String name) {
        AttributeDef def = find(name);
        if (def == null) {
            throw new DictionaryException("unknown attribute: " + name);
        }
        return def;
    }

    /** Number of attributes defined (excluding vendor nodes and the protocol root). */
    public int attributeCount() {
        return attributeCount;
    }

    /** Warnings produced while loading (lenient-mode skips, compatible redefinitions, overrides). */
    public List<String> warnings() {
        return warnings;
    }

    /** Locations of all files that were parsed, in load order. */
    public List<String> loadedFiles() {
        return loadedFiles;
    }

    static AttributeDef resolvePath(AttributeDef from, String path) {
        String rest = path.startsWith(".") ? path.substring(1) : path;
        if (rest.isEmpty()) {
            return null;
        }
        AttributeDef current = from;
        int start = 0;
        while (current != null && start <= rest.length()) {
            int dot = rest.indexOf('.', start);
            String segment = dot < 0 ? rest.substring(start) : rest.substring(start, dot);
            current = current.child(segment);
            if (dot < 0) {
                return current;
            }
            start = dot + 1;
        }
        return null;
    }

    static long vsaKey(int vendorId, int type) {
        return ((long) vendorId << 32) | (type & 0xFFFF_FFFFL);
    }
}
