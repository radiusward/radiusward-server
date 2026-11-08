/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codegen;

import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.DataType;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import io.radiusward.radius.dictionary.ParseMode;
import io.radiusward.radius.dictionary.VendorDef;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Generates Java sources from the RADIUS dictionaries and a hot-attribute list:
 *
 * <ul>
 *   <li>{@code Ietf} and one class per listed vendor with attribute numbers and {@code VALUE} constants;
 *   <li>{@code AccountingFields}, a reusable holder for the hot attributes of one packet;
 *   <li>{@code AccountingAttributeExtractor}, a single allocation-free pass that fills it.
 * </ul>
 *
 * <p>Output is deterministic and files are only rewritten when their content changes.
 *
 * <pre>
 * CodeGenerator --spec hot-attributes.txt --output target/generated-sources/radius
 *               --package io.radiusward.radius.codec.attributes [--dictionary-dir dir]...
 * </pre>
 */
public final class CodeGenerator {

    private final Dictionary dictionary;
    private final HotAttributeSpec spec;
    private final String packageName;
    private final String sourceNote;

    public CodeGenerator(Dictionary dictionary, HotAttributeSpec spec, String packageName, String sourceNote) {
        this.dictionary = dictionary;
        this.spec = spec;
        this.packageName = packageName;
        this.sourceNote = sourceNote;
    }

    public static void main(String[] args) throws IOException {
        Path specFile = null;
        Path output = null;
        String packageName = null;
        List<Path> dictionaryDirs = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String value = i + 1 < args.length ? args[i + 1] : null;
            switch (args[i]) {
                case "--spec" -> specFile = Path.of(require(value, "--spec"));
                case "--output" -> output = Path.of(require(value, "--output"));
                case "--package" -> packageName = require(value, "--package");
                case "--dictionary-dir" -> dictionaryDirs.add(Path.of(require(value, "--dictionary-dir")));
                default -> throw new IllegalArgumentException("unknown argument " + args[i]);
            }
            i++;
        }
        if (specFile == null || output == null || packageName == null) {
            throw new IllegalArgumentException(
                    "usage: --spec <file> --output <dir> --package <name> [--dictionary-dir <dir>]...");
        }
        DictionaryLoader.Builder loader = DictionaryLoader.builder().addBundledFreeRadius(ParseMode.STRICT);
        dictionaryDirs.forEach(dir -> loader.addDirectory(dir, ParseMode.LENIENT));
        Dictionary dictionary = loader.load();
        HotAttributeSpec spec = HotAttributeSpec.parse(Files.readAllLines(specFile), dictionary);
        int written = new CodeGenerator(dictionary, spec, packageName, bundledSourceNote()).writeTo(output);
        System.out.println("radius-codegen: " + written + " file(s) updated in " + output);
    }

    private static String require(String value, String option) {
        if (value == null) {
            throw new IllegalArgumentException(option + " needs a value");
        }
        return value;
    }

    /** Describes the bundled dictionary commit for the generated file headers. */
    static String bundledSourceNote() {
        Properties source = new Properties();
        try (InputStream in = CodeGenerator.class
                .getClassLoader()
                .getResourceAsStream("io/radiusward/radius/dictionary/freeradius/SOURCE.properties")) {
            if (in == null) {
                return "FreeRADIUS dictionaries";
            }
            source.load(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return "FreeRADIUS dictionaries (CC BY 4.0), commit " + source.getProperty("commit");
    }

    /** Generates all sources: file name → content. */
    public Map<String, String> generate() {
        Map<String, String> files = new LinkedHashMap<>();
        files.put("Ietf.java", constantsClass("Ietf", null, dictionary.root()));
        AttributeDef vsa = dictionary.attribute(Dictionary.VENDOR_SPECIFIC);
        for (VendorDef vendor : spec.constantVendors()) {
            AttributeDef node = vsa == null ? null : vsa.child(vendor.id());
            if (node != null) {
                files.put(
                        JavaNames.type(vendor.name()) + ".java",
                        constantsClass(JavaNames.type(vendor.name()), vendor, node));
            }
        }
        files.put("AccountingFields.java", fieldsClass());
        files.put("AccountingAttributeExtractor.java", extractorClass());
        return files;
    }

    /** Writes changed files into {@code packageName} under {@code root}. Returns the number written. */
    public int writeTo(Path root) throws IOException {
        Path dir = root.resolve(packageName.replace('.', '/'));
        Files.createDirectories(dir);
        int written = 0;
        for (Map.Entry<String, String> file : generate().entrySet()) {
            Path target = dir.resolve(file.getKey());
            if (Files.exists(target) && Files.readString(target).equals(file.getValue())) {
                continue;
            }
            Files.writeString(target, file.getValue(), StandardCharsets.UTF_8);
            written++;
        }
        return written;
    }

    // ---- constants -------------------------------------------------------------------------------

    private String constantsClass(String className, VendorDef vendor, AttributeDef parent) {
        JavaBuilder java = header();
        String subject = vendor == null ? "IETF (top-level) attributes" : vendor.name() + " vendor attributes";
        java.line("/** " + subject + ": attribute numbers and enumerated values. Generated, do not edit. */")
                .open("public final class " + className);
        if (vendor != null) {
            java.line("/** IANA private enterprise number. */")
                    .line("public static final int VENDOR_ID = " + vendor.id() + ";")
                    .blank();
        }
        List<AttributeDef> attributes = parent.children().stream()
                .filter(a -> a.number() >= 0 && a.number() <= 255 && !a.internal())
                .filter(a -> a.type() != DataType.VENDOR)
                .sorted(Comparator.comparingInt(AttributeDef::number))
                .toList();
        JavaNames.Unique names = new JavaNames.Unique();
        names.next("VENDOR_ID");
        Map<AttributeDef, String> constantNames = new LinkedHashMap<>();
        for (AttributeDef attribute : attributes) {
            String name = names.next(JavaNames.constant(attribute.name()));
            constantNames.put(attribute, name);
            java.line("/** {@code " + attribute.name() + "} ("
                            + attribute.type().dictionaryName() + "). */")
                    .line("public static final int " + name + " = " + attribute.number() + ";");
        }
        for (AttributeDef attribute : attributes) {
            if (!attribute.type().isInteger() || attribute.values().isEmpty()) {
                continue;
            }
            java.blank().line("// " + attribute.name() + " values");
            TreeMap<Long, List<String>> byValue = new TreeMap<>();
            for (Map.Entry<String, Long> value : attribute.values().entrySet()) {
                byValue.computeIfAbsent(value.getValue(), v -> new ArrayList<>())
                        .add(value.getKey());
            }
            for (Map.Entry<Long, List<String>> entry : byValue.entrySet()) {
                String canonical = attribute.valueName(entry.getKey());
                List<String> valueNames = new ArrayList<>(entry.getValue());
                // canonical (first declared) name first, aliases after it in name order
                valueNames.sort(Comparator.comparing((String key) -> !key.equalsIgnoreCase(canonical))
                        .thenComparing(Comparator.naturalOrder()));
                for (String key : valueNames) {
                    String display = key.equalsIgnoreCase(canonical) ? canonical : key;
                    String name = names.next(constantNames.get(attribute) + "_" + JavaNames.constant(display));
                    java.line("public static final long " + name + " = " + entry.getKey() + "L;");
                }
            }
        }
        java.blank().line("private " + className + "() {}").close();
        return java.toString();
    }

    // ---- fields holder ---------------------------------------------------------------------------

    private enum Kind {
        UINT8,
        UINT16,
        UINT32,
        UINT64,
        INT32,
        BYTES
    }

    private static Kind kind(AttributeDef attribute) {
        return switch (attribute.type()) {
            case UINT8, BOOL, INT8 -> Kind.UINT8;
            case UINT16, INT16 -> Kind.UINT16;
            case UINT32, DATE, TIME_DELTA, IPV4_ADDR -> Kind.UINT32;
            case UINT64, INT64, SIZE -> Kind.UINT64;
            case INT32 -> Kind.INT32;
            default -> Kind.BYTES;
        };
    }

    private static String reader(Kind kind) {
        return switch (kind) {
            case UINT8 -> "uint8";
            case UINT16 -> "uint16";
            case UINT32 -> "uint32";
            case UINT64 -> "uint64";
            case INT32 -> "int32";
            case BYTES -> throw new IllegalArgumentException();
        };
    }

    private static int expectedLength(Kind kind) {
        return switch (kind) {
            case UINT8 -> 1;
            case UINT16 -> 2;
            case UINT32, INT32 -> 4;
            case UINT64 -> 8;
            case BYTES -> -1;
        };
    }

    private static String capitalized(String name) {
        return Character.toUpperCase(name.charAt(0)) + name.substring(1);
    }

    private String fieldsClass() {
        JavaBuilder java = header();
        java.line("import org.agrona.DirectBuffer;")
                .blank()
                .line("/**")
                .line(" * Hot accounting attributes of one packet, filled by {@link AccountingAttributeExtractor}.")
                .line(" * Reusable: values are primitives and offsets into {@link #buffer()}, nothing is allocated per")
                .line(" * packet. Only valid until the packet buffer is reused. Generated, do not edit.")
                .line(" */")
                .open("public final class AccountingFields");

        List<HotAttributeSpec.Field> fields = spec.fields();
        for (int i = 0; i < fields.size(); i++) {
            HotAttributeSpec.Field field = fields.get(i);
            java.line("/** Presence bit of {@code " + field.attribute().path() + "}. */")
                    .line("public static final int " + JavaNames.fieldConstant(field.name()) + " = " + i + ";");
        }
        java.blank()
                .line("public static final int FIELD_COUNT = " + fields.size() + ";")
                .blank();
        java.line("DirectBuffer buffer;")
                .line("long present;")
                .line("int malformed;")
                .line("int dropped;");
        for (HotAttributeSpec.Field field : fields) {
            Kind kind = kind(field.attribute());
            String n = field.name();
            if (field.repeat() > 1) {
                java.line("final int[] " + n + "Offsets = new int[" + field.repeat() + "];")
                        .line("final int[] " + n + "Lengths = new int[" + field.repeat() + "];")
                        .line("int " + n + "Count;");
            } else if (kind == Kind.BYTES) {
                java.line("int " + n + "Offset;").line("int " + n + "Length;");
            } else {
                java.line("long " + n + ";");
            }
        }

        java.blank()
                .open("void reset(DirectBuffer packetBuffer)")
                .line("buffer = packetBuffer;")
                .line("present = 0;")
                .line("malformed = 0;")
                .line("dropped = 0;");
        for (HotAttributeSpec.Field field : fields) {
            if (field.repeat() > 1) {
                java.line(field.name() + "Count = 0;");
            }
        }
        java.close();

        java.blank()
                .line("/** Buffer the offsets refer to. */")
                .open("public DirectBuffer buffer()")
                .line("return buffer;")
                .close()
                .blank()
                .line("/** Whether the attribute with the given presence bit was seen with a valid value. */")
                .open("public boolean has(int field)")
                .line("return (present & (1L << field)) != 0;")
                .close()
                .blank()
                .line("/** Bit set of present fields. */")
                .open("public long presentMask()")
                .line("return present;")
                .close()
                .blank()
                .line("/** Hot attributes whose value had the wrong length; they are reported as absent. */")
                .open("public int malformedCount()")
                .line("return malformed;")
                .close()
                .blank()
                .line("/** Occurrences ignored: a second single-valued attribute or a repeat above its limit. */")
                .open("public int droppedCount()")
                .line("return dropped;")
                .close();

        for (HotAttributeSpec.Field field : fields) {
            Kind kind = kind(field.attribute());
            String n = field.name();
            String doc = "{@code " + field.attribute().path() + "}";
            java.blank();
            if (field.repeat() > 1) {
                java.line("/** Number of " + doc + " occurrences kept (at most " + field.repeat() + "). */")
                        .open("public int " + n + "Count()")
                        .line("return " + n + "Count;")
                        .close()
                        .blank()
                        .open("public int " + n + "Offset(int index)")
                        .line("return " + n + "Offsets[index];")
                        .close()
                        .blank()
                        .open("public int " + n + "Length(int index)")
                        .line("return " + n + "Lengths[index];")
                        .close();
            } else if (kind == Kind.BYTES) {
                java.line("/** Offset of the " + doc + " value in {@link #buffer()}. */")
                        .open("public int " + n + "Offset()")
                        .line("return " + n + "Offset;")
                        .close()
                        .blank()
                        .open("public int " + n + "Length()")
                        .line("return " + n + "Length;")
                        .close();
            } else {
                java.line("/** " + doc + "; check {@link #has(int)} with {@link #" + JavaNames.fieldConstant(n)
                                + "} first. */")
                        .open("public long " + n + "()")
                        .line("return " + n + ";")
                        .close();
            }
        }
        java.close();
        return java.toString();
    }

    // ---- extractor -------------------------------------------------------------------------------

    private String extractorClass() {
        JavaBuilder java = header();
        java.line("import io.radiusward.radius.codec.AttributeCursor;")
                .line("import io.radiusward.radius.codec.AttributeValues;")
                .line("import io.radiusward.radius.codec.RadiusPacket;")
                .line("import io.radiusward.radius.codec.VendorFormats;")
                .line("import org.agrona.DirectBuffer;")
                .blank()
                .line("/**")
                .line(
                        " * Single allocation-free pass over a packet that fills {@link AccountingFields}. One instance per")
                .line(" * thread. Generated, do not edit.")
                .line(" */")
                .open("public final class AccountingAttributeExtractor")
                .line("private final AttributeCursor cursor;")
                .blank()
                .open("public AccountingAttributeExtractor(VendorFormats formats)")
                .line("this.cursor = new AttributeCursor(formats);")
                .close()
                .blank()
                .line("/** Extracts the hot attributes of a validated packet into {@code out} and returns it. */")
                .open("public AccountingFields extract(RadiusPacket packet, AccountingFields out)")
                .line("out.reset(packet.buffer());")
                .line("cursor.wrap(packet);")
                .open("while (cursor.next())")
                .open("switch (cursor.vendorId())");

        Map<Integer, List<HotAttributeSpec.Field>> byVendor = new TreeMap<>();
        for (HotAttributeSpec.Field field : spec.fields()) {
            byVendor.computeIfAbsent(field.attribute().vendorId(), v -> new ArrayList<>())
                    .add(field);
        }
        for (int vendorId : byVendor.keySet()) {
            java.line("case " + vendorId + " -> " + vendorMethod(vendorId) + "(out);");
        }
        java.line("default -> {}").close().close().line("return out;").close();

        for (Map.Entry<Integer, List<HotAttributeSpec.Field>> vendor : byVendor.entrySet()) {
            java.blank()
                    .open("private void " + vendorMethod(vendor.getKey()) + "(AccountingFields out)")
                    .line("DirectBuffer buffer = cursor.buffer();")
                    .line("int offset = cursor.valueOffset();")
                    .line("int length = cursor.valueLength();")
                    .open("switch (cursor.type())");
            for (HotAttributeSpec.Field field : vendor.getValue()) {
                java.open("case " + field.attribute().number() + " ->");
                emitAssignment(java, field);
                java.close();
            }
            java.line("default -> {}").close().close();
        }
        java.close();
        return java.toString();
    }

    private static String vendorMethod(int vendorId) {
        return vendorId == 0 ? "ietf" : "vendor" + vendorId;
    }

    private void emitAssignment(JavaBuilder java, HotAttributeSpec.Field field) {
        Kind kind = kind(field.attribute());
        String n = field.name();
        String bit = "AccountingFields." + JavaNames.fieldConstant(n);
        int fixed = field.attribute().fixedLength();
        if (field.repeat() > 1) {
            java.open("if (out." + n + "Count < " + field.repeat() + ")")
                    .line("out." + n + "Offsets[out." + n + "Count] = offset;")
                    .line("out." + n + "Lengths[out." + n + "Count] = length;")
                    .line("out." + n + "Count++;")
                    .line("out.present |= 1L << " + bit + ";")
                    .closeOpen("else")
                    .line("out.dropped++;")
                    .close();
            return;
        }
        java.open("if ((out.present & (1L << " + bit + ")) != 0)").line("out.dropped++;");
        if (kind == Kind.BYTES) {
            if (fixed > 0) {
                java.closeOpen("else if (length != " + fixed + ")").line("out.malformed++;");
            }
            java.closeOpen("else")
                    .line("out." + n + "Offset = offset;")
                    .line("out." + n + "Length = length;")
                    .line("out.present |= 1L << " + bit + ";")
                    .close();
            return;
        }
        java.closeOpen("else if (length != " + expectedLength(kind) + ")")
                .line("out.malformed++;")
                .closeOpen("else")
                .line("out." + n + " = AttributeValues." + reader(kind) + "(buffer, offset, length);")
                .line("out.present |= 1L << " + bit + ";")
                .close();
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private JavaBuilder header() {
        return new JavaBuilder()
                .line("/*")
                .line(" * Generated by radius-codegen. DO NOT EDIT.")
                .line(" * Derived from " + sourceNote + ".")
                .line(" * SPDX-License-Identifier: Apache-2.0")
                .line(" */")
                .line("package " + packageName + ";")
                .blank();
    }

    /** Minimal indenting source writer. */
    static final class JavaBuilder {
        private final StringBuilder out = new StringBuilder();
        private int indent;

        JavaBuilder line(String text) {
            out.append("    ".repeat(indent)).append(text).append('\n');
            return this;
        }

        JavaBuilder blank() {
            out.append('\n');
            return this;
        }

        JavaBuilder open(String text) {
            line(text + " {");
            indent++;
            return this;
        }

        JavaBuilder close() {
            indent--;
            return line("}");
        }

        JavaBuilder closeOpen(String text) {
            indent--;
            line("} " + text + " {");
            indent++;
            return this;
        }

        @Override
        public String toString() {
            return out.toString();
        }
    }
}
