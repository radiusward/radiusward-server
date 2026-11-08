/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.attributes.AccountingAttributeExtractor;
import io.radiusward.radius.codec.attributes.AccountingFields;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.aaa4j.radius.core.packet.PacketCodec;
import org.aaa4j.radius.dictionaries.freeradius.FreeRadiusDictionary;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Runs every {@code src/test/resources/fixtures/<vendor>/<event>.fixture}:
 *
 * <ol>
 *   <li>builds the packet from its {@code attributes:} with the bundled dictionary and our encoder;
 *   <li>checks the result is byte-identical to the committed {@code packet:} hex (catches encoder drift);
 *   <li>decodes it, verifies the Request Authenticator, extracts the hot attributes and compares them
 *       with {@code expect:};
 *   <li>checks aaa4j accepts the packet.
 * </ol>
 *
 * <p>Run with {@code -Dfixtures.update=true} to (re)write the {@code packet:} lines after adding or
 * changing a fixture. Fixture format and capture guide: {@code docs/testing/strategy.md}.
 */
class VendorFixtureTest {

    private static final Path SOURCE_DIR = Path.of("src/test/resources/fixtures");
    private static final boolean UPDATE = Boolean.getBoolean("fixtures.update");

    private static Dictionary dictionary;

    @BeforeAll
    static void load() {
        dictionary = DictionaryLoader.loadBundled();
    }

    record Fixture(
            Path file,
            int identifier,
            List<Map.Entry<String, String>> attributes,
            String packetHex,
            Map<String, String> expect) {

        String name() {
            return file.getParent().getFileName() + "/" + file.getFileName();
        }
    }

    @TestFactory
    Stream<DynamicTest> fixtures() throws IOException, URISyntaxException {
        Path root = Path.of(getClass().getClassLoader().getResource("fixtures").toURI());
        List<Path> files;
        try (Stream<Path> walk = Files.walk(root)) {
            files = walk.filter(p -> p.toString().endsWith(".fixture")).sorted().toList();
        }
        assertThat(files).hasSizeGreaterThanOrEqualTo(18);
        return files.stream()
                .map(file -> DynamicTest.dynamicTest(root.relativize(file).toString(), () -> run(parse(file))));
    }

    private void run(Fixture fixture) throws Exception {
        byte[] built = build(fixture);
        if (UPDATE) {
            writePacketLine(fixture, Packets.hex(built));
        } else {
            assertThat(fixture.packetHex())
                    .as("%s has no packet: line; run with -Dfixtures.update=true", fixture.name())
                    .isNotNull();
            assertThat(Packets.hex(built))
                    .as("encoder output for %s", fixture.name())
                    .isEqualTo(fixture.packetHex());
        }

        byte[] bytes = Packets.hex(UPDATE ? Packets.hex(built) : fixture.packetHex());
        RadiusPacket packet = Packets.wrap(bytes);
        assertThat(packet.status()).isEqualTo(DecodeStatus.OK);
        assertThat(packet.code()).isEqualTo(RadiusCode.ACCOUNTING_REQUEST);
        assertThat(packet.identifier()).isEqualTo(fixture.identifier());
        assertThat(new RadiusAuthenticator().verifyAccountingRequest(packet, Packets.SECRET))
                .isTrue();

        AccountingFields fields = new AccountingAttributeExtractor(VendorFormats.from(dictionary))
                .extract(packet, new AccountingFields());
        assertThat(fields.malformedCount()).isZero();
        assertThat(fields.droppedCount()).isZero();
        for (Map.Entry<String, String> expected : fixture.expect().entrySet()) {
            assertThat(actual(fields, expected.getKey(), expected.getValue()))
                    .as("%s: %s", fixture.name(), expected.getKey())
                    .isEqualTo(expected.getValue());
        }

        new PacketCodec(new FreeRadiusDictionary()).decodeRequest(bytes, Packets.SECRET);
    }

    // ---- building ----------------------------------------------------------------------------

    private static byte[] build(Fixture fixture) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder().wrap(buffer, 0);
        encoder.header(RadiusCode.ACCOUNTING_REQUEST, fixture.identifier());
        for (Map.Entry<String, String> attribute : fixture.attributes()) {
            AttributeDef def = dictionary.require(attribute.getKey());
            byte[] value = encodeValue(def, attribute.getValue());
            if (def.vendorId() != 0) {
                encoder.vendorAttribute(def.vendorId(), def.number(), value);
            } else {
                encoder.attribute(def.number(), value);
            }
        }
        int length = encoder.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, Packets.SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    private static byte[] encodeValue(AttributeDef def, String text) {
        if (text.startsWith("0x")) {
            return Packets.hex(text.substring(2));
        }
        return switch (def.type()) {
            case UINT32, DATE -> {
                Long named = def.value(text);
                long value = named != null ? named : Long.parseLong(text);
                yield new byte[] {(byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value};
            }
            case IPV4_ADDR -> {
                String[] parts = text.split("\\.");
                byte[] address = new byte[4];
                for (int i = 0; i < 4; i++) {
                    address[i] = (byte) Integer.parseInt(parts[i]);
                }
                yield address;
            }
            case STRING, OCTETS -> text.getBytes(StandardCharsets.UTF_8);
            default -> throw new IllegalArgumentException("fixture type not supported: " + def.type() + " " + def);
        };
    }

    // ---- expectations ------------------------------------------------------------------------

    private static String actual(AccountingFields fields, String key, String expected) throws Exception {
        if (key.endsWith("Octets64")) {
            String base = key.substring(0, key.length() - "64".length());
            String giga = base.replace("Octets", "Gigawords");
            return Long.toString(AttributeValues.octets64(longValue(fields, base), longValue(fields, giga)));
        }
        assertThat(fields.has(bit(key))).as("%s present", key).isTrue();
        Method count = method(fields, key + "Count");
        if (count != null) {
            List<String> values = new ArrayList<>();
            int n = (int) count.invoke(fields);
            for (int i = 0; i < n; i++) {
                int offset = (int) method(fields, key + "Offset", int.class).invoke(fields, i);
                int length = (int) method(fields, key + "Length", int.class).invoke(fields, i);
                values.add(AttributeValues.string(fields.buffer(), offset, length));
            }
            return String.join("|", values);
        }
        Method offsetMethod = method(fields, key + "Offset");
        if (offsetMethod != null) {
            int offset = (int) offsetMethod.invoke(fields);
            int length = (int) method(fields, key + "Length").invoke(fields);
            return expected.startsWith("0x")
                    ? "0x" + AttributeValues.hex(fields.buffer(), offset, length)
                    : AttributeValues.string(fields.buffer(), offset, length);
        }
        long value = longValue(fields, key);
        return expected.chars().filter(c -> c == '.').count() == 3
                ? AttributeValues.ipv4String(value)
                : Long.toString(value);
    }

    private static long longValue(AccountingFields fields, String key) throws Exception {
        return fields.has(bit(key)) ? (long) method(fields, key).invoke(fields) : 0L;
    }

    private static int bit(String field) throws Exception {
        String constant = field.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toUpperCase(Locale.ROOT);
        return AccountingFields.class.getField(constant).getInt(null);
    }

    private static Method method(Object target, String name, Class<?>... parameters) {
        try {
            return target.getClass().getMethod(name, parameters);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    // ---- fixture files -----------------------------------------------------------------------

    static Fixture parse(Path file) throws IOException {
        int identifier = 0;
        List<Map.Entry<String, String>> attributes = new ArrayList<>();
        Map<String, String> expect = new LinkedHashMap<>();
        String packet = null;
        String section = "";
        for (String raw : Files.readAllLines(file)) {
            if (raw.isBlank() || raw.startsWith("#")) {
                continue;
            }
            boolean indented = raw.startsWith(" ");
            String line = raw.trim();
            int colon = line.indexOf(':');
            String key = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (!indented) {
                section = key;
                switch (key) {
                    case "identifier" -> identifier = Integer.parseInt(value);
                    case "packet" -> packet = value;
                    case "attributes", "expect" -> {}
                    default -> throw new IllegalArgumentException(file + ": unknown key " + key);
                }
            } else if (section.equals("attributes")) {
                attributes.add(new SimpleEntry<>(key, value));
            } else if (section.equals("expect")) {
                expect.put(key, value);
            } else {
                throw new IllegalArgumentException(file + ": unexpected indented line " + raw);
            }
        }
        return new Fixture(file, identifier, attributes, packet, expect);
    }

    /** Replaces or appends the {@code packet:} line in the fixture's source file. */
    private static void writePacketLine(Fixture fixture, String hex) throws IOException {
        Path source = SOURCE_DIR.resolve(fixture.name());
        List<String> lines = new ArrayList<>(Files.readAllLines(source));
        lines.removeIf(line -> line.startsWith("packet:"));
        int expectAt = lines.indexOf("expect:");
        lines.add(expectAt < 0 ? lines.size() : expectAt, "packet: " + hex);
        Files.write(source, lines);
    }
}
