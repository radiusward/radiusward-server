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

    private static final String PROTOCOL_RADIUS = "RADIUS";

    private enum FrameKind {
        PROTOCOL,
        VENDOR,
        BLOCK,
        SKIP
    }

    private static final class Frame {
        final FrameKind kind;
        final AttributeDef node;
        final String label;
        final String endKeyword;
        AttributeDef lastStructural;
        AttributeDef lastStruct;
        int skipDepth;

        Frame(FrameKind kind, AttributeDef node, String label, String endKeyword) {
            this.kind = kind;
            this.node = node;
            this.label = label;
            this.endKeyword = endKeyword;
        }
    }

    final AttributeDef root = AttributeDef.protocolRoot(PROTOCOL_RADIUS);
    final Int2ObjectHashMap<VendorDef> vendorsById = new Int2ObjectHashMap<>();
    final Map<String, VendorDef> vendorsByName = new HashMap<>();
    final Map<String, AttributeDef> flatNames = new HashMap<>();
    final List<String> warnings = new ArrayList<>();
    final List<String> loadedFiles = new ArrayList<>();
    final Deque<String> includeStack = new ArrayDeque<>();
    final Deque<Frame> frames = new ArrayDeque<>();
    private final DictionaryLinker linker = new DictionaryLinker(root, flatNames, warnings);

    DictionaryParser() {
        frames.push(new Frame(FrameKind.PROTOCOL, root, PROTOCOL_RADIUS, "END-PROTOCOL"));
    }

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
        int depth = frames.size();
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
        if (frames.size() != depth) {
            String open = frames.peek().kind + " " + frames.peek().label;
            while (frames.size() > depth) {
                frames.pop();
            }
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
        Frame frame = frames.peek();
        if (frame.kind == FrameKind.SKIP) {
            skipLine(frame, keyword, t);
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
            case "END-VENDOR" -> endVendor(file, t);
            case "BEGIN" -> begin(file, t);
            case "END" -> end(file, t, "END");
            case "BEGIN-PROTOCOL" -> beginProtocol(file, t, 1);
            case "END-PROTOCOL" -> endProtocol(file, t);
            case "BEGIN-TLV" -> beginBlock(file, t, 1, "END-TLV");
            case "END-TLV" -> end(file, t, "END-TLV");
            case "ALIAS" -> alias(file, t);
            case "FLAGS" -> flagsLine(file, t);
            case "PROTOCOL" -> file.requireTokens(t, 3);
            default -> file.problem("unknown keyword " + t[0]);
        }
    }

    private void skipLine(Frame frame, String keyword, String[] t) {
        boolean opensSame = switch (frame.endKeyword) {
            case "END-VENDOR" -> keyword.equals("BEGIN-VENDOR");
            case "END-PROTOCOL" ->
                keyword.equals("BEGIN-PROTOCOL")
                        || (keyword.equals("BEGIN") && t.length > 1 && t[1].equalsIgnoreCase("PROTOCOL"));
            default -> keyword.equals("BEGIN") || keyword.equals("BEGIN-TLV");
        };
        if (opensSame) {
            frame.skipDepth++;
        } else if (keyword.equals(frame.endKeyword)) {
            if (frame.skipDepth == 0) {
                frames.pop();
            } else {
                frame.skipDepth--;
            }
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
        String name = t[1];
        String numberToken = t[2];
        TypeSpec type = TypeSpec.parse(file, t[3]);
        if (type == null) {
            return;
        }
        Frame frame = frames.peek();
        AttributeFlags flags = new AttributeFlags();
        VendorDef v3Vendor = null;
        for (int i = 4; i < t.length; i++) {
            VendorDef vendor = vendorsByName.get(AttributeDef.key(t[i]));
            if (vendor != null && !t[i].contains("=")) {
                v3Vendor = vendor;
            } else if (!flags.parse(file, t[i])) {
                return;
            }
        }
        flags.internal |= file.internal;

        AttributeDef parent;
        int number;
        boolean absolute;
        if (v3Vendor != null) {
            parent = vendorNode(file, v3Vendor, vsaContainer(file, null));
            if (parent == null) {
                return;
            }
            number = file.number(numberToken);
            absolute = true;
        } else if (numberToken.startsWith(".")) {
            if (frame.lastStructural == null) {
                file.problem("relative number " + numberToken + " without a preceding tlv/struct/vsa");
                return;
            }
            Placement placement = placeDotted(file, frame.lastStructural, numberToken.substring(1));
            if (placement == null) {
                return;
            }
            parent = placement.parent;
            number = placement.number;
            absolute = false;
        } else if (numberToken.indexOf('.') > 0) {
            Placement placement = placeDotted(file, frame.node, numberToken);
            if (placement == null) {
                return;
            }
            parent = placement.parent;
            number = placement.number;
            absolute = true;
        } else {
            parent = frame.node;
            number = file.number(numberToken);
            absolute = true;
        }
        if (number < 0) {
            return;
        }

        AttributeDef def = define(file, parent, name, number, type, flags);
        if (def == null) {
            return;
        }
        if (absolute && type.type().isStructural()) {
            frame.lastStructural = def;
        }
        frame.lastStruct = type.type() == DataType.STRUCT ? def : null;
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
        Frame frame = frames.peek();
        AttributeDef def = define(file, frame.node, t[1], AttributeDef.NO_NUMBER, type, flags);
        if (def != null && type.type().isStructural()) {
            frame.lastStructural = def;
        }
    }

    private void member(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 3)) {
            return;
        }
        Frame frame = frames.peek();
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

    private record Placement(AttributeDef parent, int number) {}

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
        return number < 0 ? null : new Placement(parent, number);
    }

    // ---- VALUE -------------------------------------------------------------------------------

    private void value(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 4)) {
            return;
        }
        Frame frame = frames.peek();
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
        int typeLength = VendorDef.DEFAULT_TYPE_LENGTH;
        int lengthLength = VendorDef.DEFAULT_LENGTH_LENGTH;
        boolean continuation = false;
        for (int i = 3; i < t.length; i++) {
            if (!t[i].startsWith("format=")) {
                file.problem("unknown VENDOR option " + t[i]);
                return;
            }
            String[] format = t[i].substring("format=".length()).split(",");
            if (format.length < 2 || format.length > 3 || (format.length == 3 && !format[2].equals("c"))) {
                file.problem("malformed vendor format " + t[i]);
                return;
            }
            typeLength = file.number(format[0]);
            lengthLength = file.number(format[1]);
            continuation = format.length == 3;
        }
        VendorDef vendor;
        try {
            vendor = new VendorDef(t[1], id, typeLength, lengthLength, continuation);
        } catch (IllegalArgumentException e) {
            file.problem(e.getMessage());
            return;
        }
        VendorDef existing = vendorsById.get(id);
        if (existing != null) {
            if (existing.typeLength() != typeLength
                    || existing.lengthLength() != lengthLength
                    || existing.continuation() != continuation) {
                if (file.strict()) {
                    file.problem("vendor " + t[1] + " (" + id + ") redefined with a different format");
                    return;
                }
                warnings.add(file.at + ": vendor " + t[1] + " (" + id + ") format overridden");
                vendorsById.put(id, vendor);
                vendorsByName.put(AttributeDef.key(existing.name()), vendor);
            } else {
                vendor = existing;
            }
        } else {
            vendorsById.put(id, vendor);
        }
        vendorsByName.put(AttributeDef.key(t[1]), vendor);
    }

    private void beginVendor(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 2)) {
            return;
        }
        VendorDef vendor = vendorsByName.get(AttributeDef.key(t[1]));
        if (vendor == null) {
            file.problem("BEGIN-VENDOR for undeclared vendor " + t[1]);
            frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
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
                    frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
                    return;
                }
            } else {
                file.problem("unknown BEGIN-VENDOR option " + t[i]);
                frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
                return;
            }
        }
        AttributeDef container = extended >= 0 ? extendedVsaContainer(file, extended) : vsaContainer(file, parentPath);
        AttributeDef node = container == null ? null : vendorNode(file, vendor, container);
        if (node == null) {
            frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
            return;
        }
        frames.push(new Frame(FrameKind.VENDOR, node, vendor.name(), "END-VENDOR"));
    }

    private void endVendor(DictionaryFile file, String[] t) {
        Frame frame = frames.peek();
        if (frame.kind != FrameKind.VENDOR) {
            file.problem("END-VENDOR without BEGIN-VENDOR");
            return;
        }
        if (t.length > 1 && vendorsByName.get(AttributeDef.key(t[1])) != frame.node.vendor()) {
            file.problem("END-VENDOR " + t[1] + " does not match BEGIN-VENDOR " + frame.label);
        }
        frames.pop();
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

    // ---- BEGIN / END blocks ------------------------------------------------------------------

    private void begin(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 2)) {
            return;
        }
        if (t[1].equalsIgnoreCase("PROTOCOL")) {
            beginProtocol(file, t, 2);
        } else {
            beginBlock(file, t, 1, "END");
        }
    }

    private void beginProtocol(DictionaryFile file, String[] t, int nameIndex) {
        if (!file.requireTokens(t, nameIndex + 1)) {
            return;
        }
        String protocol = t[nameIndex];
        if (!protocol.equalsIgnoreCase(PROTOCOL_RADIUS)) {
            warnings.add(file.at + ": protocol " + protocol + " ignored");
            frames.push(new Frame(FrameKind.SKIP, null, protocol, "END-PROTOCOL"));
            return;
        }
        frames.push(new Frame(FrameKind.PROTOCOL, root, PROTOCOL_RADIUS, "END-PROTOCOL"));
    }

    private void endProtocol(DictionaryFile file, String[] t) {
        Frame frame = frames.peek();
        if (frame.kind != FrameKind.PROTOCOL || frames.size() == 1) {
            file.problem("END-PROTOCOL without BEGIN PROTOCOL");
            return;
        }
        frames.pop();
    }

    private void beginBlock(DictionaryFile file, String[] t, int refIndex, String endKeyword) {
        if (!file.requireTokens(t, refIndex + 1)) {
            return;
        }
        Frame frame = frames.peek();
        AttributeDef target = DictionaryLinker.resolveReference(frame.node, t[refIndex]);
        if (target == null) {
            target = DictionaryLinker.resolveReference(root, t[refIndex]);
        }
        if (target == null || !target.type().isStructural()) {
            file.problem(t[0] + " " + t[refIndex] + ": not a defined tlv/struct/vsa");
            frames.push(new Frame(FrameKind.SKIP, null, t[refIndex], endKeyword));
            return;
        }
        frames.push(new Frame(FrameKind.BLOCK, target, t[refIndex], endKeyword));
    }

    private void end(DictionaryFile file, String[] t, String keyword) {
        Frame frame = frames.peek();
        if (frame.kind != FrameKind.BLOCK || !frame.endKeyword.equals(keyword)) {
            file.problem(keyword + " without matching BEGIN");
            return;
        }
        if (t.length > 1 && !t[1].equalsIgnoreCase(frame.label)) {
            file.problem(keyword + " " + t[1] + " does not match BEGIN " + frame.label);
        }
        frames.pop();
    }

    // ---- ALIAS / FLAGS -----------------------------------------------------------------------

    private void alias(DictionaryFile file, String[] t) {
        if (file.requireTokens(t, 3)) {
            linker.aliasLater(frames.peek().node, t[1], t[2], file.at, file.mode);
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
