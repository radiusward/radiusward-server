/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.agrona.collections.Int2ObjectHashMap;
import org.agrona.collections.Long2ObjectHashMap;

/**
 * Parses FreeRADIUS-format dictionaries into a {@link Dictionary}.
 *
 * <p>Supports the v3 syntax used by most operator installations ({@code ATTRIBUTE}, {@code VALUE},
 * {@code VENDOR format=}, {@code BEGIN-VENDOR}/{@code END-VENDOR}, {@code BEGIN-TLV},
 * {@code $INCLUDE}, {@code $INCLUDE-}, vendor names in the fifth column) and the v4 subset used by
 * the bundled FreeRADIUS master dictionaries ({@code BEGIN PROTOCOL}, {@code BEGIN <attr>},
 * {@code END-VENDOR <name>}, {@code ALIAS}, {@code MEMBER}, {@code DEFINE}, {@code FLAGS},
 * dotted and relative attribute numbers).
 *
 * <p>Sources are loaded in the order they were added; later definitions extend or override earlier
 * ones. See {@code docs/dictionaries.md}.
 */
public final class DictionaryLoader {

    private static final String PROTOCOL_RADIUS = "RADIUS";

    private static final Set<String> KNOWN_FLAGS = Set.of(
            "has_tag",
            "encrypt",
            "concat",
            "internal",
            "array",
            "counter",
            "ref",
            "clone",
            "abinary",
            "secret",
            "precision",
            "extended",
            "long_extended",
            "enum",
            "key",
            "virtual",
            "length");

    private final List<Entry> entries;

    private DictionaryLoader(List<Entry> entries) {
        this.entries = List.copyOf(entries);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Loads only the bundled FreeRADIUS dictionaries in strict mode. */
    public static Dictionary loadBundled() {
        return builder()
                .add(DictionarySource.bundledFreeRadius(), ParseMode.STRICT)
                .load();
    }

    /** Builder collecting dictionary sources in load order. */
    public static final class Builder {
        private final List<Entry> entries = new ArrayList<>();
        private ParseMode defaultMode = ParseMode.LENIENT;

        private Builder() {}

        /** Mode used by {@link #add(DictionarySource)} and {@link #addDirectory(Path)}. Defaults to lenient. */
        public Builder mode(ParseMode mode) {
            this.defaultMode = mode;
            return this;
        }

        public Builder add(DictionarySource source) {
            return add(source, defaultMode);
        }

        public Builder add(DictionarySource source, ParseMode mode) {
            entries.add(new Entry(source, mode, false));
            return this;
        }

        /** Adds the bundled FreeRADIUS dictionaries. */
        public Builder addBundledFreeRadius(ParseMode mode) {
            return add(DictionarySource.bundledFreeRadius(), mode);
        }

        /**
         * Adds every regular, non-hidden file in {@code directory} in name order, e.g.
         * {@code /etc/radiusward/dictionary.d/}. A missing directory is ignored with a warning.
         */
        public Builder addDirectory(Path directory) {
            return addDirectory(directory, defaultMode);
        }

        public Builder addDirectory(Path directory, ParseMode mode) {
            if (!Files.isDirectory(directory)) {
                entries.add(new Entry(DictionarySource.file(directory), mode, true));
                return this;
            }
            try (Stream<Path> files = Files.list(directory)) {
                files.filter(Files::isRegularFile)
                        .filter(p -> !p.getFileName().toString().startsWith("."))
                        .sorted()
                        .forEach(p -> entries.add(new Entry(DictionarySource.file(p), mode, false)));
            } catch (IOException e) {
                throw new DictionaryException("cannot list dictionary directory " + directory, e);
            }
            return this;
        }

        public Dictionary load() {
            return new DictionaryLoader(entries).load();
        }
    }

    private record Entry(DictionarySource source, ParseMode mode, boolean missingDirectory) {}

    private Dictionary load() {
        Parser parser = new Parser();
        for (Entry entry : entries) {
            if (entry.missingDirectory()) {
                parser.warnings.add("dictionary directory not found, skipped: "
                        + entry.source().location());
                continue;
            }
            parser.parseTopLevel(entry.source(), entry.mode());
        }
        return parser.finish();
    }

    // ------------------------------------------------------------------------------------------

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

    private record Location(String file, int line) {
        @Override
        public String toString() {
            return file + ":" + line;
        }
    }

    private record PendingAlias(AttributeDef context, String name, String target, Location at, ParseMode mode) {}

    private record PendingValue(
            AttributeDef context, String attribute, String name, String value, Location at, ParseMode mode) {}

    private static final class Parser {
        final AttributeDef root = AttributeDef.protocolRoot(PROTOCOL_RADIUS);
        final Int2ObjectHashMap<VendorDef> vendorsById = new Int2ObjectHashMap<>();
        final Map<String, VendorDef> vendorsByName = new HashMap<>();
        final Map<String, AttributeDef> flatNames = new HashMap<>();
        final List<String> warnings = new ArrayList<>();
        final List<String> loadedFiles = new ArrayList<>();
        final List<PendingAlias> pendingAliases = new ArrayList<>();
        final List<PendingValue> pendingValues = new ArrayList<>();
        final Deque<String> includeStack = new ArrayDeque<>();
        final Deque<Frame> frames = new ArrayDeque<>();

        Parser() {
            frames.push(new Frame(FrameKind.PROTOCOL, root, PROTOCOL_RADIUS, "END-PROTOCOL"));
        }

        void parseTopLevel(DictionarySource source, ParseMode mode) {
            if (!source.exists()) {
                throw new DictionaryException("dictionary not found: " + source.location());
            }
            parseFile(source, mode, null);
        }

        private void parseFile(DictionarySource source, ParseMode mode, Location includedFrom) {
            String identity = source.identity();
            if (includeStack.contains(identity)) {
                throw new DictionaryException(
                        includedFrom + ": $INCLUDE cycle: " + String.join(" -> ", includeStack) + " -> " + identity);
            }
            includeStack.addLast(identity);
            loadedFiles.add(source.location());
            int depth = frames.size();
            FileState file = new FileState(source, mode);
            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(source.open(), StandardCharsets.UTF_8))) {
                String line;
                int lineNo = 0;
                while ((line = reader.readLine()) != null) {
                    lineNo++;
                    String[] tokens = tokenize(line);
                    if (tokens.length > 0) {
                        file.at = new Location(source.location(), lineNo);
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
                problem(file, "unterminated block at end of file: " + open);
            }
        }

        private static final class FileState {
            final DictionarySource source;
            final ParseMode mode;
            boolean internal;
            Location at;

            FileState(DictionarySource source, ParseMode mode) {
                this.source = source;
                this.mode = mode;
            }

            boolean strict() {
                return mode == ParseMode.STRICT;
            }
        }

        /** Strict mode: fail. Lenient mode: record a warning and continue. */
        private void problem(FileState file, String message) {
            if (file.strict()) {
                throw new DictionaryException(file.at + ": " + message);
            }
            warnings.add(file.at + ": " + message + " (skipped)");
        }

        private static String[] tokenize(String line) {
            int hash = line.indexOf('#');
            String content = (hash >= 0 ? line.substring(0, hash) : line).trim();
            if (content.isEmpty()) {
                return new String[0];
            }
            return content.split("\\s+");
        }

        private void parseLine(FileState file, String[] t) {
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
                case "PROTOCOL" -> requireTokens(file, t, 3);
                default -> problem(file, "unknown keyword " + t[0]);
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

        private boolean requireTokens(FileState file, String[] t, int min) {
            if (t.length < min) {
                problem(file, t[0] + " needs at least " + (min - 1) + " arguments");
                return false;
            }
            return true;
        }

        // ---- $INCLUDE ------------------------------------------------------------------------

        private void include(FileState file, String[] t, boolean optional) {
            if (!requireTokens(file, t, 2)) {
                return;
            }
            DictionarySource target = file.source.resolve(t[1]);
            if (!target.exists()) {
                if (!optional) {
                    problem(file, "$INCLUDE target not found: " + target.location());
                }
                return;
            }
            parseFile(target, file.mode, file.at);
        }

        // ---- ATTRIBUTE / DEFINE / MEMBER -------------------------------------------------------

        private void attribute(FileState file, String[] t) {
            if (!requireTokens(file, t, 4)) {
                return;
            }
            String name = t[1];
            String numberToken = t[2];
            TypeSpec type = typeSpec(file, t[3]);
            if (type == null) {
                return;
            }
            Frame frame = frames.peek();
            Flags flags = new Flags();
            VendorDef v3Vendor = null;
            for (int i = 4; i < t.length; i++) {
                VendorDef vendor = vendorsByName.get(AttributeDef.key(t[i]));
                if (vendor != null && !t[i].contains("=")) {
                    v3Vendor = vendor;
                } else if (!flags.parse(this, file, t[i])) {
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
                number = parseNumber(file, numberToken);
                absolute = true;
            } else if (numberToken.startsWith(".")) {
                if (frame.lastStructural == null) {
                    problem(file, "relative number " + numberToken + " without a preceding tlv/struct/vsa");
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
                number = parseNumber(file, numberToken);
                absolute = true;
            }
            if (number < 0) {
                return;
            }

            AttributeDef def = define(file, parent, name, number, type, flags);
            if (def == null) {
                return;
            }
            if (absolute && type.type.isStructural()) {
                frame.lastStructural = def;
            }
            frame.lastStruct = type.type == DataType.STRUCT ? def : null;
        }

        private void define(FileState file, String[] t) {
            if (!requireTokens(file, t, 3)) {
                return;
            }
            TypeSpec type = typeSpec(file, t[2]);
            if (type == null) {
                return;
            }
            Flags flags = new Flags();
            for (int i = 3; i < t.length; i++) {
                if (!flags.parse(this, file, t[i])) {
                    return;
                }
            }
            flags.internal |= file.internal;
            Frame frame = frames.peek();
            AttributeDef def = define(file, frame.node, t[1], AttributeDef.NO_NUMBER, type, flags);
            if (def != null && type.type.isStructural()) {
                frame.lastStructural = def;
            }
        }

        private void member(FileState file, String[] t) {
            if (!requireTokens(file, t, 3)) {
                return;
            }
            Frame frame = frames.peek();
            if (frame.lastStruct == null) {
                problem(file, "MEMBER " + t[1] + " without a preceding struct");
                return;
            }
            TypeSpec type = typeSpec(file, t[2]);
            if (type == null) {
                return;
            }
            boolean key = false;
            for (int i = 3; i < t.length; i++) {
                for (String flag : t[i].split(",")) {
                    String flagName = flag.contains("=") ? flag.substring(0, flag.indexOf('=')) : flag;
                    if (flagName.equals("key")) {
                        key = true;
                    } else if (!KNOWN_FLAGS.contains(flagName)) {
                        problem(file, "unknown flag " + flag);
                        return;
                    }
                }
            }
            AttributeDef struct = frame.lastStruct;
            struct.addMember(new AttributeDef.MemberDef(t[1], type.type, type.length, key));
            // members are addressable by name, e.g. BEGIN Vendor-Specific.3GPP.User-Location-Info.Data
            if (struct.child(t[1]) == null) {
                AttributeDef node =
                        new AttributeDef(t[1], AttributeDef.NO_NUMBER, type.type, type.length, struct, struct.vendor());
                struct.addChild(node);
            }
        }

        private AttributeDef define(
                FileState file, AttributeDef parent, String name, int number, TypeSpec type, Flags flags) {
            if (parent.type() == DataType.VSA && type.type != DataType.VENDOR) {
                problem(
                        file,
                        "attribute " + name + " cannot be a direct child of " + parent.path()
                                + "; declare it inside BEGIN-VENDOR");
                return null;
            }
            VendorDef vendor = parent.vendor();

            AttributeDef existing = number == AttributeDef.NO_NUMBER ? null : parent.child(number);
            if (existing != null) {
                if (existing.type() == type.type) {
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
                    problem(
                            file,
                            "attribute " + name + " (" + number + ") redefines " + existing + " with a different type "
                                    + type.type.dictionaryName());
                    return null;
                }
                warnings.add(
                        file.at + ": " + name + " overrides " + existing + " with type " + type.type.dictionaryName());
                AttributeDef replacement = new AttributeDef(name, number, type.type, type.length, parent, vendor);
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
                    problem(file, "attribute " + name + " already defined as " + sameName);
                    return null;
                }
                warnings.add(file.at + ": " + name + " renumbered from " + sameName.oid() + " to " + number);
                AttributeDef replacement = new AttributeDef(name, number, type.type, type.length, parent, vendor);
                flags.apply(replacement);
                parent.replaceChild(sameName, replacement);
                flatNames.put(AttributeDef.key(name), replacement);
                return replacement;
            }

            AttributeDef def = new AttributeDef(name, number, type.type, type.length, parent, vendor);
            flags.apply(def);
            parent.addChild(def);
            flatNames.putIfAbsent(AttributeDef.key(name), def);
            return def;
        }

        private record Placement(AttributeDef parent, int number) {}

        /** Walks {@code a.b.c} from {@code from}: {@code a.b} must exist, {@code c} is the new number. */
        private Placement placeDotted(FileState file, AttributeDef from, String dotted) {
            String[] parts = dotted.split("\\.");
            AttributeDef parent = from;
            for (int i = 0; i < parts.length - 1; i++) {
                int n = parseNumber(file, parts[i]);
                if (n < 0) {
                    return null;
                }
                AttributeDef next = parent.child(n);
                if (next == null && parent.type() == DataType.VSA) {
                    VendorDef vendor = vendorsById.get(n);
                    next = vendor == null ? null : vendorNode(file, vendor, parent);
                }
                if (next == null) {
                    problem(file, "parent " + n + " not defined under " + parent.path() + " for " + dotted);
                    return null;
                }
                parent = next;
            }
            int number = parseNumber(file, parts[parts.length - 1]);
            return number < 0 ? null : new Placement(parent, number);
        }

        private record TypeSpec(DataType type, int length) {}

        private TypeSpec typeSpec(FileState file, String token) {
            DataType type = DataType.fromDictionaryName(token);
            if (type == null) {
                problem(file, "unknown data type " + token);
                return null;
            }
            int length = -1;
            int bracket = token.indexOf('[');
            if (bracket >= 0) {
                if (!token.endsWith("]")) {
                    problem(file, "malformed type " + token);
                    return null;
                }
                length = parseNumber(file, token.substring(bracket + 1, token.length() - 1));
                if (length < 0) {
                    return null;
                }
            }
            return new TypeSpec(type, length);
        }

        private final class Flags {
            boolean hasTag;
            boolean concat;
            boolean internal;
            boolean array;
            String encrypt;
            final Map<String, String> options = new LinkedHashMap<>();

            boolean parse(Parser parser, FileState file, String token) {
                for (String flag : token.split(",")) {
                    if (flag.isEmpty()) {
                        continue;
                    }
                    int eq = flag.indexOf('=');
                    String name = eq >= 0 ? flag.substring(0, eq) : flag;
                    String value = eq >= 0 ? flag.substring(eq + 1) : "";
                    if (!KNOWN_FLAGS.contains(name)) {
                        parser.problem(file, "unknown flag " + flag);
                        return !file.strict();
                    }
                    switch (name) {
                        case "has_tag" -> hasTag = true;
                        case "concat" -> concat = true;
                        case "internal" -> internal = true;
                        case "array" -> array = true;
                        case "encrypt" -> encrypt = encryptName(value);
                        default -> options.put(name, value);
                    }
                }
                return true;
            }

            void apply(AttributeDef def) {
                def.flags(hasTag, concat, internal, array, encrypt, options);
            }
        }

        private static String encryptName(String value) {
            return switch (value) {
                case "1" -> "User-Password";
                case "2" -> "Tunnel-Password";
                case "3" -> "Ascend-Secret";
                default -> value;
            };
        }

        // ---- VALUE -------------------------------------------------------------------------------

        private void value(FileState file, String[] t) {
            if (!requireTokens(file, t, 4)) {
                return;
            }
            Frame frame = frames.peek();
            AttributeDef context = frame.node;
            // VALUE lines directly after a struct may name one of its members
            AttributeDef target = frame.lastStruct == null ? null : frame.lastStruct.child(t[1]);
            if (target == null) {
                target = lookup(context, t[1]);
            }
            if (target == null) {
                pendingValues.add(new PendingValue(context, t[1], t[2], t[3], file.at, file.mode));
                return;
            }
            addValue(target, t[2], t[3], file.at, file.mode);
        }

        private void addValue(AttributeDef target, String name, String raw, Location at, ParseMode mode) {
            Long value = parseValue(target.type(), raw);
            if (value == null) {
                String message = at + ": VALUE " + name + "=" + raw + " is not valid for " + target;
                if (mode == ParseMode.STRICT) {
                    throw new DictionaryException(message);
                }
                warnings.add(message + " (skipped)");
                return;
            }
            target.addValue(name, value);
        }

        private static Long parseValue(DataType type, String raw) {
            if (type.isInteger() || type == DataType.OCTETS || type == DataType.STRING) {
                Long number = parseLong(raw);
                if (number != null) {
                    return number;
                }
            }
            if (type == DataType.IPV4_ADDR) {
                String[] octets = raw.split("\\.");
                if (octets.length == 4) {
                    long v = 0;
                    for (String o : octets) {
                        Long part = parseLong(o);
                        if (part == null || part < 0 || part > 255) {
                            return null;
                        }
                        v = (v << 8) | part;
                    }
                    return v;
                }
            }
            return null;
        }

        // ---- VENDOR ------------------------------------------------------------------------------

        private void vendor(FileState file, String[] t) {
            if (!requireTokens(file, t, 3)) {
                return;
            }
            int id = parseNumber(file, t[2]);
            if (id < 0) {
                return;
            }
            int typeLength = VendorDef.DEFAULT_TYPE_LENGTH;
            int lengthLength = VendorDef.DEFAULT_LENGTH_LENGTH;
            boolean continuation = false;
            for (int i = 3; i < t.length; i++) {
                if (!t[i].startsWith("format=")) {
                    problem(file, "unknown VENDOR option " + t[i]);
                    return;
                }
                String[] format = t[i].substring("format=".length()).split(",");
                if (format.length < 2 || format.length > 3 || (format.length == 3 && !format[2].equals("c"))) {
                    problem(file, "malformed vendor format " + t[i]);
                    return;
                }
                typeLength = parseNumber(file, format[0]);
                lengthLength = parseNumber(file, format[1]);
                continuation = format.length == 3;
            }
            VendorDef vendor;
            try {
                vendor = new VendorDef(t[1], id, typeLength, lengthLength, continuation);
            } catch (IllegalArgumentException e) {
                problem(file, e.getMessage());
                return;
            }
            VendorDef existing = vendorsById.get(id);
            if (existing != null) {
                if (existing.typeLength() != typeLength
                        || existing.lengthLength() != lengthLength
                        || existing.continuation() != continuation) {
                    if (file.strict()) {
                        problem(file, "vendor " + t[1] + " (" + id + ") redefined with a different format");
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

        private void beginVendor(FileState file, String[] t) {
            if (!requireTokens(file, t, 2)) {
                return;
            }
            VendorDef vendor = vendorsByName.get(AttributeDef.key(t[1]));
            if (vendor == null) {
                problem(file, "BEGIN-VENDOR for undeclared vendor " + t[1]);
                frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
                return;
            }
            String parentPath = null;
            for (int i = 2; i < t.length; i++) {
                if (t[i].startsWith("parent=")) {
                    parentPath = t[i].substring("parent=".length());
                } else if (t[i].startsWith("format=Extended-Vendor-Specific-")) {
                    int n = parseNumber(file, t[i].substring("format=Extended-Vendor-Specific-".length()));
                    parentPath = (240 + n) + "." + Dictionary.VENDOR_SPECIFIC;
                } else {
                    problem(file, "unknown BEGIN-VENDOR option " + t[i]);
                    frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
                    return;
                }
            }
            AttributeDef container = vsaContainer(file, parentPath);
            AttributeDef node = container == null ? null : vendorNode(file, vendor, container);
            if (node == null) {
                frames.push(new Frame(FrameKind.SKIP, null, t[1], "END-VENDOR"));
                return;
            }
            frames.push(new Frame(FrameKind.VENDOR, node, vendor.name(), "END-VENDOR"));
        }

        private void endVendor(FileState file, String[] t) {
            Frame frame = frames.peek();
            if (frame.kind != FrameKind.VENDOR) {
                problem(file, "END-VENDOR without BEGIN-VENDOR");
                return;
            }
            if (t.length > 1 && vendorsByName.get(AttributeDef.key(t[1])) != frame.node.vendor()) {
                problem(file, "END-VENDOR " + t[1] + " does not match BEGIN-VENDOR " + frame.label);
            }
            frames.pop();
        }

        /** The VSA attribute vendor nodes hang off: RFC 2865 Vendor-Specific (26) unless a parent path is given. */
        private AttributeDef vsaContainer(FileState file, String parentPath) {
            AttributeDef container;
            if (parentPath == null) {
                container = root.child(Dictionary.VENDOR_SPECIFIC);
                if (container == null) {
                    // operator files may be loaded without the RFC dictionaries
                    container = new AttributeDef(
                            "Vendor-Specific", Dictionary.VENDOR_SPECIFIC, DataType.VSA, -1, root, null);
                    root.addChild(container);
                    flatNames.putIfAbsent(AttributeDef.key(container.name()), container);
                }
            } else {
                container = resolveReference(root, parentPath);
                if (container == null) {
                    problem(file, "vendor parent " + parentPath + " not defined");
                    return null;
                }
            }
            if (container.type() != DataType.VSA && container.type() != DataType.EVS) {
                problem(file, "vendor parent " + container + " is not a vsa");
                return null;
            }
            return container;
        }

        private AttributeDef vendorNode(FileState file, VendorDef vendor, AttributeDef container) {
            if (container == null) {
                return null;
            }
            AttributeDef node = container.child(vendor.id());
            if (node == null) {
                node = new AttributeDef(vendor.name(), vendor.id(), DataType.VENDOR, -1, container, vendor);
                container.addChild(node);
            } else if (node.type() != DataType.VENDOR) {
                problem(file, "vendor " + vendor.name() + " collides with " + node);
                return null;
            }
            return node;
        }

        // ---- BEGIN / END blocks ------------------------------------------------------------------

        private void begin(FileState file, String[] t) {
            if (!requireTokens(file, t, 2)) {
                return;
            }
            if (t[1].equalsIgnoreCase("PROTOCOL")) {
                beginProtocol(file, t, 2);
            } else {
                beginBlock(file, t, 1, "END");
            }
        }

        private void beginProtocol(FileState file, String[] t, int nameIndex) {
            if (!requireTokens(file, t, nameIndex + 1)) {
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

        private void endProtocol(FileState file, String[] t) {
            Frame frame = frames.peek();
            if (frame.kind != FrameKind.PROTOCOL || frames.size() == 1) {
                problem(file, "END-PROTOCOL without BEGIN PROTOCOL");
                return;
            }
            frames.pop();
        }

        private void beginBlock(FileState file, String[] t, int refIndex, String endKeyword) {
            if (!requireTokens(file, t, refIndex + 1)) {
                return;
            }
            Frame frame = frames.peek();
            AttributeDef target = resolveReference(frame.node, t[refIndex]);
            if (target == null) {
                target = resolveReference(root, t[refIndex]);
            }
            if (target == null || !target.type().isStructural()) {
                problem(file, t[0] + " " + t[refIndex] + ": not a defined tlv/struct/vsa");
                frames.push(new Frame(FrameKind.SKIP, null, t[refIndex], endKeyword));
                return;
            }
            frames.push(new Frame(FrameKind.BLOCK, target, t[refIndex], endKeyword));
        }

        private void end(FileState file, String[] t, String keyword) {
            Frame frame = frames.peek();
            if (frame.kind != FrameKind.BLOCK || !frame.endKeyword.equals(keyword)) {
                problem(file, keyword + " without matching BEGIN");
                return;
            }
            if (t.length > 1 && !t[1].equalsIgnoreCase(frame.label)) {
                problem(file, keyword + " " + t[1] + " does not match BEGIN " + frame.label);
            }
            frames.pop();
        }

        // ---- ALIAS / FLAGS -----------------------------------------------------------------------

        private void alias(FileState file, String[] t) {
            if (requireTokens(file, t, 3)) {
                pendingAliases.add(new PendingAlias(frames.peek().node, t[1], t[2], file.at, file.mode));
            }
        }

        private void flagsLine(FileState file, String[] t) {
            for (int i = 1; i < t.length; i++) {
                for (String flag : t[i].split(",")) {
                    switch (flag) {
                        case "internal" -> file.internal = true;
                        case "-internal" -> file.internal = false;
                        default -> problem(file, "unknown FLAGS value " + flag);
                    }
                }
            }
        }

        // ---- lookups -----------------------------------------------------------------------------

        private AttributeDef lookup(AttributeDef context, String ref) {
            AttributeDef def = resolveReference(context, ref);
            if (def == null && context != root) {
                def = resolveReference(root, ref);
            }
            if (def == null) {
                def = flatNames.get(AttributeDef.key(ref));
            }
            return def;
        }

        private static AttributeDef resolveReference(AttributeDef context, String ref) {
            String path = ref.startsWith("@") ? ref.substring(1) : ref;
            return Dictionary.resolvePath(context, path);
        }

        // ---- numbers -----------------------------------------------------------------------------

        private int parseNumber(FileState file, String token) {
            Long value = parseLong(token);
            if (value == null || value < 0 || value > 0xFFFF_FFFFL) {
                problem(file, "invalid number " + token);
                return -1;
            }
            return (int) (long) value;
        }

        private static Long parseLong(String token) {
            try {
                if (token.startsWith("0x") || token.startsWith("0X")) {
                    return Long.parseUnsignedLong(token.substring(2), 16);
                }
                return Long.parseLong(token);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        // ---- finish ------------------------------------------------------------------------------

        Dictionary finish() {
            resolveAliases();
            for (PendingValue pending : pendingValues) {
                AttributeDef target = lookup(pending.context(), pending.attribute());
                if (target == null) {
                    String message = pending.at() + ": VALUE for undefined attribute " + pending.attribute();
                    if (pending.mode() == ParseMode.STRICT) {
                        throw new DictionaryException(message);
                    }
                    warnings.add(message + " (skipped)");
                    continue;
                }
                addValue(target, pending.name(), pending.value(), pending.at(), pending.mode());
            }

            Long2ObjectHashMap<AttributeDef> vsaIndex = new Long2ObjectHashMap<>();
            AttributeDef vsa = root.child(Dictionary.VENDOR_SPECIFIC);
            if (vsa != null) {
                for (AttributeDef vendorNode : vsa.children()) {
                    for (AttributeDef attr : vendorNode.children()) {
                        vsaIndex.put(Dictionary.vsaKey(vendorNode.number(), attr.number()), attr);
                    }
                }
            }
            Map<String, VendorDef> vendorNames = new HashMap<>(vendorsByName);
            return new Dictionary(
                    root,
                    vendorsById,
                    vendorNames,
                    vsaIndex,
                    flatNames,
                    warnings,
                    loadedFiles,
                    countAttributes(root, new HashSet<>()));
        }

        private void resolveAliases() {
            List<PendingAlias> remaining = new ArrayList<>(pendingAliases);
            boolean progress = true;
            while (!remaining.isEmpty() && progress) {
                progress = false;
                for (var it = remaining.iterator(); it.hasNext(); ) {
                    PendingAlias alias = it.next();
                    AttributeDef target = lookup(alias.context(), alias.target());
                    if (target != null) {
                        if (!alias.context().hasNameOrAlias(alias.name())) {
                            alias.context().addAlias(alias.name(), target);
                        }
                        flatNames.putIfAbsent(AttributeDef.key(alias.name()), target);
                        it.remove();
                        progress = true;
                    }
                }
            }
            for (PendingAlias alias : remaining) {
                String message = alias.at() + ": ALIAS " + alias.name() + " target not found: " + alias.target();
                if (alias.mode() == ParseMode.STRICT) {
                    throw new DictionaryException(message);
                }
                warnings.add(message + " (skipped)");
            }
        }

        private static int countAttributes(AttributeDef node, Set<AttributeDef> seen) {
            int count = 0;
            for (AttributeDef child : node.children()) {
                if (!seen.add(child)) {
                    continue;
                }
                if (child.type() != DataType.VENDOR) {
                    count++;
                }
                count += countAttributes(child, seen);
            }
            return count;
        }
    }
}
