/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.agrona.collections.Int2ObjectHashMap;

/**
 * The parser behind {@link DictionaryLoader}: reads FreeRADIUS-format files (v3 and the v4 subset) into the attribute
 * tree, resolving aliases and values that came before their attribute.
 */
final class DictionaryParser {

    static final String PROTOCOL_RADIUS = "RADIUS";

    final AttributeDef root = AttributeDef.protocolRoot(PROTOCOL_RADIUS);
    final Int2ObjectHashMap<VendorDef> vendorsById = new Int2ObjectHashMap<>();
    final Map<String, VendorDef> vendorsByName = new HashMap<>();
    final Map<String, AttributeDef> flatNames = new HashMap<>();
    final List<String> warnings = new ArrayList<>();
    final List<String> loadedFiles = new ArrayList<>();
    final Deque<String> includeStack = new ArrayDeque<>();
    private final BlockStack blocks = new BlockStack(root);
    private final DictionaryLinker linker = new DictionaryLinker(root, flatNames, warnings);

    void parseTopLevel(DictionarySource source, ParseMode mode) {
        if (!source.exists()) {
            throw new DictionaryException("dictionary not found: " + source.location());
        }
        parseFile(source, mode, null);
    }

    private void parseFile(DictionarySource source, ParseMode mode, DictionaryFile.Location includedFrom) {
        String identity = source.identity();
        if (includeStack.contains(identity)) {
            throw new DictionaryException(
                    includedFrom + ": $INCLUDE cycle: " + String.join(" -> ", includeStack) + " -> " + identity);
        }
        includeStack.addLast(identity);
        loadedFiles.add(source.location());
        int depth = blocks.depth();
        DictionaryFile file = new DictionaryFile(source, mode, warnings);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(source.open(), StandardCharsets.UTF_8))) {
            String line;
            int lineNo = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                String[] tokens = tokenize(line);
                if (tokens.length > 0) {
                    file.at = new DictionaryFile.Location(source.location(), lineNo);
                    parseLine(file, tokens);
                }
            }
        } catch (IOException e) {
            throw new DictionaryException("cannot read " + source.location(), e);
        } finally {
            includeStack.removeLast();
        }
        String open = blocks.closeTo(depth);
        if (open != null) {
            file.problem("unterminated block at end of file: " + open);
        }
    }

    private static String[] tokenize(String line) {
        int hash = line.indexOf('#');
        String content = (hash >= 0 ? line.substring(0, hash) : line).trim();
        if (content.isEmpty()) {
            return new String[0];
        }
        return content.split("\\s+");
    }

    private void parseLine(DictionaryFile file, String[] t) {
        String keyword = t[0].toUpperCase(Locale.ROOT);
        if (blocks.skipping()) {
            blocks.skipLine(keyword, t);
            return;
        }
        switch (keyword) {
            case "$INCLUDE" -> include(file, t, false);
            case "$INCLUDE-" -> include(file, t, true);
            case "ATTRIBUTE" -> attribute(file, t);
            case "DEFINE" -> define(file, t);
            case "MEMBER" -> member(file, t);
            case "VALUE" -> value(file, t);
            case "VENDOR" -> vendor(file, t);
            case "BEGIN-VENDOR" -> beginVendor(file, t);
            case "END-VENDOR" ->
                blocks.endVendor(file, t, t.length > 1 ? vendorsByName.get(AttributeDef.key(t[1])) : null);
            case "BEGIN" -> blocks.begin(file, t);
            case "END" -> blocks.end(file, t, "END");
            case "BEGIN-PROTOCOL" -> blocks.beginProtocol(file, t, 1);
            case "END-PROTOCOL" -> blocks.endProtocol(file);
            case "BEGIN-TLV" -> blocks.beginBlock(file, t, 1, "END-TLV");
            case "END-TLV" -> blocks.end(file, t, "END-TLV");
            case "ALIAS" -> alias(file, t);
            case "FLAGS" -> flagsLine(file, t);
            case "PROTOCOL" -> file.requireTokens(t, 3);
            default -> file.problem("unknown keyword " + t[0]);
        }
    }

    // ---- $INCLUDE ------------------------------------------------------------------------

    private void include(DictionaryFile file, String[] t, boolean optional) {
        if (!file.requireTokens(t, 2)) {
            return;
        }
        DictionarySource target = file.source.resolve(t[1]);
        if (!target.exists()) {
            if (!optional) {
                file.problem("$INCLUDE target not found: " + target.location());
            }
            return;
        }
        parseFile(target, file.mode, file.at);
    }

    // ---- ATTRIBUTE / DEFINE / MEMBER -------------------------------------------------------

    private void attribute(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 4)) {
            return;
        }
        TypeSpec type = TypeSpec.parse(file, t[3]);
        if (type == null) {
            return;
        }
        AttributeFlags flags = new AttributeFlags();
        VendorDef v3Vendor = null;
        for (int i = 4; i < t.length; i++) {
            VendorDef vendor = vendorsByName.get(AttributeDef.key(t[i]));
            if (vendor != null && !t[i].contains("=")) {
                v3Vendor = vendor; // v3: ATTRIBUTE <name> <number> <type> <vendor>
            } else if (!flags.parse(file, t[i])) {
                return;
            }
        }
        flags.internal |= file.internal;
        BlockStack.Frame frame = blocks.top();
        Placement at = place(file, frame, t[2], v3Vendor);
        if (at == null) {
            return;
        }
        AttributeDef def = define(file, at.parent(), t[1], at.number(), type, flags);
        if (def == null) {
            return;
        }
        if (at.absolute() && type.type().isStructural()) {
            frame.lastStructural = def;
        }
        frame.lastStruct = type.type() == DataType.STRUCT ? def : null;
    }

    /**
     * Where an ATTRIBUTE goes: under a v3 vendor; relative to the last tlv/struct/vsa ({@code .2}); at a dotted path
     * from the block ({@code 26.9.1}); or in the block. {@code null} after a problem.
     */
    private Placement place(DictionaryFile file, BlockStack.Frame frame, String numberToken, VendorDef v3Vendor) {
        if (v3Vendor != null) {
            AttributeDef parent = vendorNode(file, v3Vendor, vsaContainer(file, null));
            return parent == null ? null : numbered(file, parent, numberToken);
        }
        if (numberToken.startsWith(".")) {
            if (frame.lastStructural == null) {
                file.problem("relative number " + numberToken + " without a preceding tlv/struct/vsa");
                return null;
            }
            Placement p = placeDotted(file, frame.lastStructural, numberToken.substring(1));
            return p == null ? null : new Placement(p.parent(), p.number(), false);
        }
        if (numberToken.indexOf('.') > 0) {
            return placeDotted(file, frame.node, numberToken);
        }
        return numbered(file, frame.node, numberToken);
    }

    private static Placement numbered(DictionaryFile file, AttributeDef parent, String numberToken) {
        int number = file.number(numberToken);
        return number < 0 ? null : new Placement(parent, number, true);
    }

    private void define(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 3)) {
            return;
        }
        TypeSpec type = TypeSpec.parse(file, t[2]);
        if (type == null) {
            return;
        }
        AttributeFlags flags = new AttributeFlags();
        for (int i = 3; i < t.length; i++) {
            if (!flags.parse(file, t[i])) {
                return;
            }
        }
        flags.internal |= file.internal;
        BlockStack.Frame frame = blocks.top();
        AttributeDef def = define(file, frame.node, t[1], AttributeDef.NO_NUMBER, type, flags);
        if (def != null && type.type().isStructural()) {
            frame.lastStructural = def;
        }
    }

    private void member(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 3)) {
            return;
        }
        BlockStack.Frame frame = blocks.top();
        if (frame.lastStruct == null) {
            file.problem("MEMBER " + t[1] + " without a preceding struct");
            return;
        }
        TypeSpec type = TypeSpec.parse(file, t[2]);
        if (type == null) {
            return;
        }
        boolean key = false;
        for (int i = 3; i < t.length; i++) {
            for (String flag : t[i].split(",")) {
                String flagName = flag.contains("=") ? flag.substring(0, flag.indexOf('=')) : flag;
                if (flagName.equals("key")) {
                    key = true;
                } else if (!AttributeFlags.known(flagName)) {
                    file.problem("unknown flag " + flag);
                    return;
                }
            }
        }
        AttributeDef struct = frame.lastStruct;
        struct.addMember(new AttributeDef.MemberDef(t[1], type.type(), type.length(), key));
        // members are addressable by name, e.g. BEGIN Vendor-Specific.3GPP.User-Location-Info.Data
        if (struct.child(t[1]) == null) {
            AttributeDef node =
                    new AttributeDef(t[1], AttributeDef.NO_NUMBER, type.type(), type.length(), struct, struct.vendor());
            struct.addChild(node);
        }
    }

    private AttributeDef define(
            DictionaryFile file, AttributeDef parent, String name, int number, TypeSpec type, AttributeFlags flags) {
        if (parent.type() == DataType.VSA && type.type() != DataType.VENDOR) {
            file.problem("attribute " + name + " cannot be a direct child of " + parent.path()
                    + "; declare it inside BEGIN-VENDOR");
            return null;
        }
        VendorDef vendor = parent.vendor();

        AttributeDef existing = number == AttributeDef.NO_NUMBER ? null : parent.child(number);
        if (existing != null) {
            if (existing.type() == type.type()) {
                // compatible redefinition, typically a v3 operator file re-declaring a bundled attribute
                if (!existing.name().equalsIgnoreCase(name)) {
                    existing.addAlternateName(name);
                    if (!parent.hasNameOrAlias(name)) {
                        parent.addAlias(name, existing);
                    }
                    flatNames.putIfAbsent(AttributeDef.key(name), existing);
                }
                return existing;
            }
            if (file.strict()) {
                file.problem("attribute " + name + " (" + number + ") redefines " + existing + " with a different type "
                        + type.type().dictionaryName());
                return null;
            }
            file.warn(name + " overrides " + existing + " with type "
                    + type.type().dictionaryName());
            AttributeDef replacement = new AttributeDef(name, number, type.type(), type.length(), parent, vendor);
            flags.apply(replacement);
            parent.replaceChild(existing, replacement);
            flatNames.put(AttributeDef.key(name), replacement);
            return replacement;
        }

        AttributeDef sameName = parent.child(name);
        if (sameName != null && sameName.parent() == parent) {
            if (sameName.number() == number && number == AttributeDef.NO_NUMBER) {
                return sameName;
            }
            if (file.strict()) {
                file.problem("attribute " + name + " already defined as " + sameName);
                return null;
            }
            file.warn(name + " renumbered from " + sameName.oid() + " to " + number);
            AttributeDef replacement = new AttributeDef(name, number, type.type(), type.length(), parent, vendor);
            flags.apply(replacement);
            parent.replaceChild(sameName, replacement);
            flatNames.put(AttributeDef.key(name), replacement);
            return replacement;
        }

        AttributeDef def = new AttributeDef(name, number, type.type(), type.length(), parent, vendor);
        flags.apply(def);
        parent.addChild(def);
        flatNames.putIfAbsent(AttributeDef.key(name), def);
        return def;
    }

    /** @param absolute numbered from the block, not relative to the last tlv/struct/vsa */
    private record Placement(AttributeDef parent, int number, boolean absolute) {}

    /** Walks {@code a.b.c} from {@code from}: {@code a.b} must exist, {@code c} is the new number. */
    private Placement placeDotted(DictionaryFile file, AttributeDef from, String dotted) {
        String[] parts = dotted.split("\\.");
        AttributeDef parent = from;
        for (int i = 0; i < parts.length - 1; i++) {
            int n = file.number(parts[i]);
            if (n < 0) {
                return null;
            }
            AttributeDef next = parent.child(n);
            if (next == null && parent.type() == DataType.VSA) {
                VendorDef vendor = vendorsById.get(n);
                next = vendor == null ? null : vendorNode(file, vendor, parent);
            }
            if (next == null) {
                file.problem("parent " + n + " not defined under " + parent.path() + " for " + dotted);
                return null;
            }
            parent = next;
        }
        int number = file.number(parts[parts.length - 1]);
        return number < 0 ? null : new Placement(parent, number, true);
    }

    // ---- VALUE -------------------------------------------------------------------------------

    private void value(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 4)) {
            return;
        }
        BlockStack.Frame frame = blocks.top();
        AttributeDef context = frame.node;
        // VALUE lines directly after a struct may name one of its members
        AttributeDef target = frame.lastStruct == null ? null : frame.lastStruct.child(t[1]);
        if (target == null) {
            target = linker.lookup(context, t[1]);
        }
        if (target == null) {
            linker.valueLater(context, t[1], t[2], t[3], file.at, file.mode);
            return;
        }
        linker.addValue(target, t[2], t[3], file.at, file.mode);
    }

    // ---- VENDOR ------------------------------------------------------------------------------

    private void vendor(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 3)) {
            return;
        }
        int id = file.number(t[2]);
        if (id < 0) {
            return;
        }
        VendorFormat format = vendorFormat(file, t);
        if (format == null) {
            return;
        }
        VendorDef vendor;
        try {
            vendor = new VendorDef(t[1], id, format.typeLength(), format.lengthLength(), format.continuation());
        } catch (IllegalArgumentException e) {
            file.problem(e.getMessage());
            return;
        }
        register(file, vendor);
    }

    private record VendorFormat(int typeLength, int lengthLength, boolean continuation) {}

    /** {@code format=<type length>,<length length>[,c]}; RFC 2865's 1,1 without one; {@code null} after a problem. */
    private static VendorFormat vendorFormat(DictionaryFile file, String[] t) {
        VendorFormat format = new VendorFormat(VendorDef.DEFAULT_TYPE_LENGTH, VendorDef.DEFAULT_LENGTH_LENGTH, false);
        for (int i = 3; i < t.length; i++) {
            if (!t[i].startsWith("format=")) {
                file.problem("unknown VENDOR option " + t[i]);
                return null;
            }
            String[] parts = t[i].substring("format=".length()).split(",");
            if (parts.length < 2 || parts.length > 3 || (parts.length == 3 && !parts[2].equals("c"))) {
                file.problem("malformed vendor format " + t[i]);
                return null;
            }
            format = new VendorFormat(file.number(parts[0]), file.number(parts[1]), parts.length == 3);
        }
        return format;
    }

    /**
     * Registers a vendor by number and name. The same number again with the same format is the same vendor (another
     * name for it); with another format it fails in strict mode and replaces the vendor in lenient mode.
     */
    private void register(DictionaryFile file, VendorDef vendor) {
        VendorDef existing = vendorsById.get(vendor.id());
        if (existing == null) {
            vendorsById.put(vendor.id(), vendor);
        } else if (existing.typeLength() == vendor.typeLength()
                && existing.lengthLength() == vendor.lengthLength()
                && existing.continuation() == vendor.continuation()) {
            vendorsByName.put(AttributeDef.key(vendor.name()), existing);
            return;
        } else if (file.strict()) {
            file.problem("vendor " + vendor.name() + " (" + vendor.id() + ") redefined with a different format");
            return;
        } else {
            file.warn("vendor " + vendor.name() + " (" + vendor.id() + ") format overridden");
            vendorsById.put(vendor.id(), vendor);
            vendorsByName.put(AttributeDef.key(existing.name()), vendor);
        }
        vendorsByName.put(AttributeDef.key(vendor.name()), vendor);
    }

    private void beginVendor(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 2)) {
            return;
        }
        VendorDef vendor = vendorsByName.get(AttributeDef.key(t[1]));
        if (vendor == null) {
            file.problem("BEGIN-VENDOR for undeclared vendor " + t[1]);
            blocks.skip(t[1], "END-VENDOR");
            return;
        }
        String parentPath = null;
        int extended = -1;
        for (int i = 2; i < t.length; i++) {
            if (t[i].startsWith("parent=")) {
                parentPath = t[i].substring("parent=".length());
            } else if (t[i].startsWith("format=Extended-Vendor-Specific-")) {
                extended = file.number(t[i].substring("format=Extended-Vendor-Specific-".length()));
                if (extended < 0) {
                    blocks.skip(t[1], "END-VENDOR");
                    return;
                }
            } else {
                file.problem("unknown BEGIN-VENDOR option " + t[i]);
                blocks.skip(t[1], "END-VENDOR");
                return;
            }
        }
        AttributeDef container = extended >= 0 ? extendedVsaContainer(file, extended) : vsaContainer(file, parentPath);
        AttributeDef node = container == null ? null : vendorNode(file, vendor, container);
        if (node == null) {
            blocks.skip(t[1], "END-VENDOR");
            return;
        }
        blocks.open(BlockStack.Kind.VENDOR, node, vendor.name(), "END-VENDOR");
    }

    /** The VSA attribute vendor nodes hang off: RFC 2865 Vendor-Specific (26) unless a parent path is given. */
    private AttributeDef vsaContainer(DictionaryFile file, String parentPath) {
        AttributeDef container;
        if (parentPath == null) {
            container = root.child(Dictionary.VENDOR_SPECIFIC);
            if (container == null) {
                // operator files may be loaded without the RFC dictionaries
                container =
                        new AttributeDef("Vendor-Specific", Dictionary.VENDOR_SPECIFIC, DataType.VSA, -1, root, null);
                root.addChild(container);
                flatNames.putIfAbsent(AttributeDef.key(container.name()), container);
            }
        } else {
            container = DictionaryLinker.resolveReference(root, parentPath);
            if (container == null) {
                file.problem("vendor parent " + parentPath + " not defined");
                return null;
            }
        }
        if (container.type() != DataType.VSA && container.type() != DataType.EVS) {
            file.problem("vendor parent " + container + " is not a vsa");
            return null;
        }
        return container;
    }

    /**
     * The Vendor-Specific attribute (26) inside Extended-Attribute-{@code n} (240 + n, RFC 6929), for v3's
     * {@code BEGIN-VENDOR <name> format=Extended-Vendor-Specific-<n>}: found by number, as the v3 files name the
     * attributes differently.
     */
    private AttributeDef extendedVsaContainer(DictionaryFile file, int n) {
        AttributeDef extended = n < 1 || n > 6 ? null : root.child(240 + n);
        AttributeDef container = extended == null ? null : extended.child(Dictionary.VENDOR_SPECIFIC);
        if (container == null) {
            file.problem("vendor parent Extended-Vendor-Specific-" + n + " (" + (240 + n) + "."
                    + Dictionary.VENDOR_SPECIFIC + ") not defined");
            return null;
        }
        if (container.type() != DataType.VSA && container.type() != DataType.EVS) {
            file.problem("vendor parent " + container + " is not a vsa");
            return null;
        }
        return container;
    }

    private AttributeDef vendorNode(DictionaryFile file, VendorDef vendor, AttributeDef container) {
        if (container == null) {
            return null;
        }
        AttributeDef node = container.child(vendor.id());
        if (node == null) {
            node = new AttributeDef(vendor.name(), vendor.id(), DataType.VENDOR, -1, container, vendor);
            container.addChild(node);
        } else if (node.type() != DataType.VENDOR) {
            file.problem("vendor " + vendor.name() + " collides with " + node);
            return null;
        }
        return node;
    }

    // ---- ALIAS / FLAGS -----------------------------------------------------------------------

    private void alias(DictionaryFile file, String[] t) {
        if (file.requireTokens(t, 3)) {
            linker.aliasLater(blocks.top().node, t[1], t[2], file.at, file.mode);
        }
    }

    private void flagsLine(DictionaryFile file, String[] t) {
        for (int i = 1; i < t.length; i++) {
            for (String flag : t[i].split(",")) {
                switch (flag) {
                    case "internal" -> file.internal = true;
                    case "-internal" -> file.internal = false;
                    default -> file.problem("unknown FLAGS value " + flag);
                }
            }
        }
    }

    /** The dictionary: aliases and values that came before their attribute resolved now. */
    Dictionary finish() {
        return linker.link(vendorsById, vendorsByName, loadedFiles);
    }
}
