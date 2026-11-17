/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Every kind of malformed line the parser reports: in lenient mode a warning and the line skipped, in strict mode a
 * failure at that line (or, for what only deserves a note, a warning in both modes).
 */
class DictionaryProblemsTest {

    /** A small dictionary the bad lines are added to: a vsa, a tlv, an integer, a struct, a vendor. */
    private static final String BASE = """
            ATTRIBUTE User-Name 1 string
            ATTRIBUTE Vendor-Specific 26 vsa
            ATTRIBUTE Group 100 tlv
            ATTRIBUTE Record 102 struct
            ATTRIBUTE Plain 101 integer
            VENDOR Acme 9999
            """;

    /**
     * @param lines added after {@link #BASE} unless {@code alone}
     * @param warning what strict mode fails with
     * @param lenient what lenient mode warns: the same, or how it overrides an earlier definition
     * @param fails whether strict mode fails; otherwise both modes only warn
     */
    record Case(String name, String lines, String warning, String lenient, boolean fails, boolean alone) {
        @Override
        public String toString() {
            return name;
        }
    }

    private static Case bad(String name, String lines, String warning) {
        return new Case(name, lines, warning, warning, true, false);
    }

    /** Strict mode fails; lenient mode takes the line over the earlier definition. */
    private static Case overrides(String name, String lines, String warning, String lenient) {
        return new Case(name, lines, warning, lenient, true, false);
    }

    static Stream<Case> cases() {
        return Stream.of(
                bad("ATTRIBUTE without its type", "ATTRIBUTE Only 103", "ATTRIBUTE needs at least 3 arguments"),
                bad("unknown type", "ATTRIBUTE X 103 nonsense", "unknown data type nonsense"),
                bad("unknown flag", "ATTRIBUTE X 103 string shiny", "unknown flag shiny"),
                new Case(
                        "relative number without a tlv",
                        "ATTRIBUTE X .1 string",
                        "relative number .1 without a preceding tlv/struct/vsa",
                        "relative number .1 without a preceding tlv/struct/vsa",
                        true,
                        true),
                bad(
                        "dotted path through an undefined parent",
                        "ATTRIBUTE X 100.7.1 string",
                        "parent 7 not defined under"),
                bad("dotted path with a bad number", "ATTRIBUTE X 100.x string", "invalid number x"),
                bad("unknown vendor in a dotted VSA path", "ATTRIBUTE X 26.4242.1 string", "parent 4242 not defined"),
                bad("plain attribute under the VSA", "ATTRIBUTE X 26.5 string", "cannot be a direct child of"),
                overrides(
                        "another type for a number",
                        "ATTRIBUTE Other 101 string",
                        "redefines",
                        "Other overrides Plain"),
                overrides(
                        "a name again with another number",
                        "ATTRIBUTE Plain 200 integer",
                        "already defined as",
                        "Plain renumbered from 101 to 200"),
                bad("DEFINE without its type", "DEFINE X", "DEFINE needs at least 2 arguments"),
                bad("DEFINE of an unknown type", "DEFINE X nonsense", "unknown data type nonsense"),
                bad("DEFINE with an unknown flag", "DEFINE X string shiny", "unknown flag shiny"),
                bad("MEMBER without its type", "MEMBER A", "MEMBER needs at least 2 arguments"),
                bad("MEMBER without a struct", "MEMBER A uint8", "MEMBER A without a preceding struct"),
                bad("MEMBER of an unknown type", "ATTRIBUTE R2 103 struct\nMEMBER A nonsense", "unknown data type"),
                bad(
                        "MEMBER with an unknown flag",
                        "ATTRIBUTE R2 103 struct\nMEMBER A uint8 shiny",
                        "unknown flag shiny"),
                bad("VALUE without its value", "VALUE Plain One", "VALUE needs at least 3 arguments"),
                bad("VENDOR without its number", "VENDOR Only", "VENDOR needs at least 2 arguments"),
                bad("VENDOR with a bad number", "VENDOR X y", "invalid number y"),
                bad("VENDOR with an unknown option", "VENDOR X 77 shape=1", "unknown VENDOR option shape=1"),
                bad("VENDOR with a malformed format", "VENDOR X 77 format=1", "malformed vendor format format=1"),
                bad("VENDOR with an impossible format", "VENDOR X 77 format=3,1", "invalid vendor type length 3 for X"),
                overrides(
                        "a vendor again with another format",
                        "VENDOR Acme 9999 format=2,2",
                        "redefined with a different format",
                        "vendor Acme (9999) format overridden"),
                bad("BEGIN-VENDOR without a vendor", "BEGIN-VENDOR", "BEGIN-VENDOR needs at least 1 arguments"),
                bad(
                        "BEGIN-VENDOR under an undefined parent",
                        "BEGIN-VENDOR Acme parent=Nowhere\nEND-VENDOR Acme",
                        "vendor parent Nowhere not defined"),
                bad("BEGIN-VENDOR under a non-vsa", "BEGIN-VENDOR Acme parent=Plain\nEND-VENDOR Acme", "is not a vsa"),
                bad(
                        "BEGIN-VENDOR in a missing extended VSA",
                        "BEGIN-VENDOR Acme format=Extended-Vendor-Specific-9\nEND-VENDOR Acme",
                        "vendor parent Extended-Vendor-Specific-9"),
                bad("END-VENDOR without BEGIN-VENDOR", "END-VENDOR Acme", "END-VENDOR without BEGIN-VENDOR"),
                bad("a block left open", "BEGIN-VENDOR Acme", "unterminated block at end of file: VENDOR Acme"),
                bad("$INCLUDE without a file", "$INCLUDE", "$INCLUDE needs at least 1 arguments"),
                bad("$INCLUDE of a missing file", "$INCLUDE nowhere.dictionary", "$INCLUDE target not found"),
                bad("END-TLV without BEGIN-TLV", "END-TLV", "END-TLV without matching BEGIN"),
                bad("PROTOCOL without its number", "PROTOCOL RADIUS", "PROTOCOL needs at least 2 arguments"),
                bad("an unknown FLAGS value", "FLAGS shiny", "unknown FLAGS value shiny"),
                new Case(
                        "another protocol",
                        "BEGIN-PROTOCOL DHCPv4\nATTRIBUTE Anything 1 string\nEND-PROTOCOL DHCPv4",
                        "protocol DHCPv4 ignored",
                        "protocol DHCPv4 ignored",
                        false,
                        false));
    }

    @TempDir
    Path dir;

    private Path write(Case c) throws IOException {
        return Files.writeString(dir.resolve("dictionary"), (c.alone() ? "" : BASE) + c.lines() + "\n");
    }

    private static Dictionary load(Path file, ParseMode mode) {
        return DictionaryLoader.builder().add(DictionarySource.file(file), mode).load();
    }

    @ParameterizedTest
    @MethodSource("cases")
    void lenientModeWarnsAndSkipsTheLine(Case c) throws IOException {
        Dictionary d = load(write(c), ParseMode.LENIENT);
        assertThat(d.warnings()).anySatisfy(w -> assertThat(w).contains(c.lenient()));
        if (!c.alone()) {
            assertThat(d.attribute(1).name()).as("the rest is read").isEqualTo("User-Name");
        }
    }

    @ParameterizedTest
    @MethodSource("cases")
    void strictModeFailsAtTheLine(Case c) throws IOException {
        Path file = write(c);
        if (c.fails()) {
            assertThatThrownBy(() -> load(file, ParseMode.STRICT))
                    .isInstanceOf(DictionaryException.class)
                    .hasMessageContaining(c.warning());
        } else {
            assertThat(load(file, ParseMode.STRICT).warnings())
                    .anySatisfy(w -> assertThat(w).contains(c.warning()));
        }
    }
}
