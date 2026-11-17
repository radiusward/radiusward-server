/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The parser's parts on their own: numbers, VALUE values, types, flags, and how a file reports problems. */
class DictionaryPartsTest {

    private final List<String> warnings = new ArrayList<>();

    private DictionaryFile file(ParseMode mode) {
        DictionaryFile file = new DictionaryFile(null, mode, warnings);
        file.at = new DictionaryFile.Location("dictionary.test", 7);
        return file;
    }

    @Test
    void numbersAndValues() {
        assertThat(DictionaryNumbers.parseLong("26")).isEqualTo(26);
        assertThat(DictionaryNumbers.parseLong("0x1A")).isEqualTo(26);
        assertThat(DictionaryNumbers.parseLong("0XffFFffFF")).isEqualTo(0xFFFF_FFFFL);
        assertThat(DictionaryNumbers.parseLong("twenty")).isNull();
        assertThat(DictionaryNumbers.parseValue(DataType.UINT32, "3")).isEqualTo(3);
        assertThat(DictionaryNumbers.parseValue(DataType.IPV4_ADDR, "10.0.0.1")).isEqualTo(0x0A000001L);
        assertThat(DictionaryNumbers.parseValue(DataType.IPV4_ADDR, "10.0.0.256"))
                .isNull();
        assertThat(DictionaryNumbers.parseValue(DataType.IPV4_ADDR, "10.0.1")).isNull();
        assertThat(DictionaryNumbers.parseValue(DataType.UINT32, "x")).isNull();
    }

    @Test
    void aFileReportsProblemsByItsMode() {
        DictionaryFile lenient = file(ParseMode.LENIENT);
        assertThat(lenient.number("0x10")).isEqualTo(16);
        assertThat(lenient.number("-1")).isEqualTo(-1);
        assertThat(lenient.number("0x100000000")).as("beyond 32 bits").isEqualTo(-1);
        assertThat(lenient.requireTokens(new String[] {"VALUE", "a"}, 4)).isFalse();
        lenient.warn("noted");
        assertThat(warnings)
                .containsExactly(
                        "dictionary.test:7: invalid number -1 (skipped)",
                        "dictionary.test:7: invalid number 0x100000000 (skipped)",
                        "dictionary.test:7: VALUE needs at least 3 arguments (skipped)",
                        "dictionary.test:7: noted");
        assertThatThrownBy(() -> file(ParseMode.STRICT).number("x"))
                .isInstanceOf(DictionaryException.class)
                .hasMessage("dictionary.test:7: invalid number x");
    }

    @Test
    void typesWithAndWithoutALength() {
        DictionaryFile f = file(ParseMode.LENIENT);
        assertThat(TypeSpec.parse(f, "octets")).isEqualTo(new TypeSpec(DataType.OCTETS, -1));
        assertThat(TypeSpec.parse(f, "octets[16]")).isEqualTo(new TypeSpec(DataType.OCTETS, 16));
        assertThat(TypeSpec.parse(f, "octets[16")).isNull();
        assertThat(TypeSpec.parse(f, "nonsense")).isNull();
        assertThat(warnings).hasSize(2);
    }

    @Test
    void flagsOfAnAttribute() {
        AttributeFlags flags = new AttributeFlags();
        assertThat(flags.parse(file(ParseMode.STRICT), "has_tag,encrypt=2,,array,precision=2"))
                .isTrue();
        assertThat(flags.hasTag).isTrue();
        assertThat(flags.array).isTrue();
        assertThat(flags.encrypt).as("encrypt=2 is Tunnel-Password's method").isEqualTo("Tunnel-Password");
        assertThat(flags.options).containsEntry("precision", "2");
        assertThat(AttributeFlags.known("concat")).isTrue();
        assertThat(AttributeFlags.known("shiny")).isFalse();
        assertThat(new AttributeFlags().parse(file(ParseMode.LENIENT), "shiny"))
                .as("lenient: the flag is skipped, the line kept")
                .isTrue();
        assertThatThrownBy(() -> new AttributeFlags().parse(file(ParseMode.STRICT), "shiny"))
                .isInstanceOf(DictionaryException.class);
    }

    @Test
    void skippedBlocksAreReadOnlyToTheirEnd() {
        AttributeDef root = AttributeDef.protocolRoot(DictionaryParser.PROTOCOL_RADIUS);
        BlockStack blocks = new BlockStack(root);
        DictionaryFile f = file(ParseMode.LENIENT);
        blocks.beginProtocol(f, new String[] {"BEGIN-PROTOCOL", "DHCPv4"}, 1);
        assertThat(blocks.skipping()).as("another protocol").isTrue();
        assertThat(warnings).containsExactly("dictionary.test:7: protocol DHCPv4 ignored");
        blocks.skipLine("BEGIN-PROTOCOL", new String[] {"BEGIN-PROTOCOL", "DHCPv6"});
        blocks.skipLine("ATTRIBUTE", new String[] {"ATTRIBUTE", "x", "1", "string"});
        blocks.skipLine("END-PROTOCOL", new String[] {"END-PROTOCOL"});
        assertThat(blocks.skipping()).as("the nested one ended").isTrue();
        blocks.skipLine("END-PROTOCOL", new String[] {"END-PROTOCOL"});
        assertThat(blocks.skipping()).isFalse();
        assertThat(blocks.depth()).isEqualTo(1);
        assertThat(blocks.top().node).isSameAs(root);
    }

    @Test
    void blocksMustBeClosedByTheirOwnEnd() {
        AttributeDef root = AttributeDef.protocolRoot(DictionaryParser.PROTOCOL_RADIUS);
        BlockStack blocks = new BlockStack(root);
        DictionaryFile f = file(ParseMode.LENIENT);
        blocks.beginBlock(f, new String[] {"BEGIN-TLV", "Nowhere"}, 1, "END-TLV");
        assertThat(blocks.skipping()).as("not a defined tlv").isTrue();
        blocks.skipLine("END-TLV", new String[] {"END-TLV"});
        blocks.end(f, new String[] {"END"}, "END");
        blocks.endProtocol(f);
        assertThat(warnings)
                .containsExactly(
                        "dictionary.test:7: BEGIN-TLV Nowhere: not a defined tlv/struct/vsa (skipped)",
                        "dictionary.test:7: END without matching BEGIN (skipped)",
                        "dictionary.test:7: END-PROTOCOL without BEGIN PROTOCOL (skipped)");
        int depth = blocks.depth();
        blocks.skip("Unknown-Vendor", "END-VENDOR");
        assertThat(blocks.closeTo(depth)).as("left open by a file").isEqualTo("SKIP Unknown-Vendor");
        assertThat(blocks.closeTo(depth)).isNull();
    }
}
