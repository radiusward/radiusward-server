/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.agrona.collections.Int2ObjectHashMap;
import org.agrona.collections.Long2ObjectHashMap;

/**
 * One node of the attribute tree.
 *
 * <p>The tree mirrors FreeRADIUS v4: the protocol root holds the top-level attributes;
 * {@code Vendor-Specific} (26) holds one {@link DataType#VENDOR} node per vendor, whose children are
 * that vendor's attributes; TLVs and extended attributes hold their sub-attributes.
 *
 * <p>Instances are only mutated while a {@link DictionaryLoader} builds them; a loaded
 * {@link Dictionary} never changes, so lookups are safe from any thread.
 */
public final class AttributeDef {

    /** Number used for attributes that have no wire number ({@code DEFINE}, protocol root). */
    public static final int NO_NUMBER = -1;

    private final String name;
    private final int number;
    private final DataType type;
    private final int fixedLength;
    private final AttributeDef parent;
    private final VendorDef vendor;

    private boolean hasTag;
    private boolean concat;
    private boolean internal;
    private boolean array;
    private String encrypt;
    private Map<String, String> options = Map.of();

    private final Int2ObjectHashMap<AttributeDef> childrenByNumber = new Int2ObjectHashMap<>();
    private final Map<String, AttributeDef> childrenByName = new HashMap<>();
    private final Map<String, AttributeDef> aliases = new HashMap<>();
    private final List<String> alternateNames = new ArrayList<>(0);
    private final List<MemberDef> members = new ArrayList<>(0);
    private final Long2ObjectHashMap<String> valueNames = new Long2ObjectHashMap<>();
    private final Map<String, Long> valuesByName = new LinkedHashMap<>();

    AttributeDef(String name, int number, DataType type, int fixedLength, AttributeDef parent, VendorDef vendor) {
        this.name = name;
        this.number = number;
        this.type = type;
        this.fixedLength = fixedLength;
        this.parent = parent;
        this.vendor = vendor;
    }

    static AttributeDef protocolRoot(String protocol) {
        return new AttributeDef(protocol, NO_NUMBER, DataType.TLV, -1, null, null);
    }

    /** Attribute name as declared, unique among its siblings. */
    public String name() {
        return name;
    }

    /** Wire number relative to the parent, or {@link #NO_NUMBER}. */
    public int number() {
        return number;
    }

    public DataType type() {
        return type;
    }

    /** Fixed value length from a {@code type[n]} declaration, or {@code -1}. */
    public int fixedLength() {
        return fixedLength;
    }

    /** Parent node; {@code null} only for the protocol root. */
    public AttributeDef parent() {
        return parent;
    }

    /** Vendor this attribute belongs to, or {@code null} for IETF attributes. */
    public VendorDef vendor() {
        return vendor;
    }

    /** Vendor id, or {@code 0} for IETF attributes. */
    public int vendorId() {
        return vendor == null ? 0 : vendor.id();
    }

    public boolean isProtocolRoot() {
        return parent == null;
    }

    /** Whether this is a direct child of the protocol root (a "classic" RFC 2865 attribute). */
    public boolean isTopLevel() {
        return parent != null && parent.parent == null;
    }

    public boolean hasTag() {
        return hasTag;
    }

    public boolean concat() {
        return concat;
    }

    /** Whether the attribute is server-internal and never appears on the wire. */
    public boolean internal() {
        return internal;
    }

    public boolean array() {
        return array;
    }

    /** Encryption method ({@code User-Password}, {@code Tunnel-Password}, {@code Ascend-Secret}), or {@code null}. */
    public String encrypt() {
        return encrypt;
    }

    /** Remaining {@code key=value} or bare flags such as {@code ref}, {@code clone}, {@code counter}. */
    public Map<String, String> options() {
        return options;
    }

    /** Dotted name path from the protocol root, e.g. {@code Vendor-Specific.Cisco.AVPair}. */
    public String path() {
        if (parent == null) {
            return name;
        }
        if (parent.parent == null) {
            return name;
        }
        return parent.path() + "." + name;
    }

    /** Dotted number path from the protocol root, e.g. {@code 26.9.1}. */
    public String oid() {
        if (parent == null || parent.parent == null) {
            return Integer.toString(number);
        }
        return parent.oid() + "." + number;
    }

    /** Child attribute with the given wire number, or {@code null}. Allocation-free. */
    public AttributeDef child(int childNumber) {
        return childrenByNumber.get(childNumber);
    }

    /** Child attribute or alias with the given name (case-insensitive), or {@code null}. */
    public AttributeDef child(String childName) {
        String key = key(childName);
        AttributeDef child = childrenByName.get(key);
        return child != null ? child : aliases.get(key);
    }

    public Collection<AttributeDef> children() {
        return Collections.unmodifiableCollection(childrenByNumber.values());
    }

    /** Additional names this attribute is known by (compatible redefinitions from v3 files). */
    public List<String> alternateNames() {
        return Collections.unmodifiableList(alternateNames);
    }

    /** Struct members in wire order; empty for non-struct attributes. */
    public List<MemberDef> members() {
        return Collections.unmodifiableList(members);
    }

    /** Name of the enumerated value, or {@code null}. Allocation-free for values in the map. */
    public String valueName(long value) {
        return valueNames.get(value);
    }

    /** Numeric value of an enumerated name (case-insensitive), or {@code null}. */
    public Long value(String valueName) {
        return valuesByName.get(key(valueName));
    }

    /** Enumerated values in declaration order, keyed by lower-case name. */
    public Map<String, Long> values() {
        return Collections.unmodifiableMap(valuesByName);
    }

    @Override
    public String toString() {
        return path() + " (" + oid() + ", " + type.dictionaryName() + ")";
    }

    // ---- mutation, used only by DictionaryLoader -------------------------------------------------

    void flags(
            boolean hasTag, boolean concat, boolean internal, boolean array, String encrypt, Map<String, String> opts) {
        this.hasTag = hasTag;
        this.concat = concat;
        this.internal = internal;
        this.array = array;
        this.encrypt = encrypt;
        this.options = opts.isEmpty() ? Map.of() : Map.copyOf(opts);
    }

    void addChild(AttributeDef child) {
        if (child.number != NO_NUMBER) {
            childrenByNumber.put(child.number, child);
        }
        childrenByName.put(key(child.name), child);
    }

    void replaceChild(AttributeDef previous, AttributeDef replacement) {
        childrenByName.remove(key(previous.name));
        if (previous.number != NO_NUMBER) {
            childrenByNumber.remove(previous.number);
        }
        addChild(replacement);
    }

    void addAlias(String aliasName, AttributeDef target) {
        aliases.put(key(aliasName), target);
    }

    boolean hasNameOrAlias(String candidate) {
        String key = key(candidate);
        return childrenByName.containsKey(key) || aliases.containsKey(key);
    }

    void addAlternateName(String alternate) {
        if (!alternate.equalsIgnoreCase(name) && !alternateNames.contains(alternate)) {
            alternateNames.add(alternate);
        }
    }

    void addMember(MemberDef member) {
        members.add(member);
    }

    void addValue(String valueName, long value) {
        valuesByName.put(key(valueName), value);
        valueNames.putIfAbsent(value, valueName);
    }

    static String key(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    /**
     * A struct member declared with {@code MEMBER name type [flags]}.
     *
     * @param name member name
     * @param type member data type
     * @param fixedLength length from {@code type[n]} (bits for {@link DataType#BIT}), or {@code -1}
     * @param key whether this member selects the union variant that follows
     */
    public record MemberDef(String name, DataType type, int fixedLength, boolean key) {}
}
