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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DictionaryLoaderTest {

    @TempDir
    Path dir;

    private Path write(String name, String... lines) throws IOException {
        Path file = dir.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, String.join("\n", lines) + "\n");
        return file;
    }

    private Dictionary strict(Path file) {
        return DictionaryLoader.builder()
                .add(DictionarySource.file(file), ParseMode.STRICT)
                .load();
    }

    private Dictionary lenient(Path file) {
        return DictionaryLoader.builder()
                .add(DictionarySource.file(file), ParseMode.LENIENT)
                .load();
    }

    private static final String[] RFC_BASE = {
        "ATTRIBUTE User-Name 1 string",
        "ATTRIBUTE Vendor-Specific 26 vsa",
        "ATTRIBUTE Acct-Status-Type 40 integer",
        "VALUE Acct-Status-Type Start 1",
        "VALUE Acct-Status-Type Stop 2",
    };

    @Nested
    class Attributes {

        @Test
        void topLevelAttributesAndValues() throws IOException {
            Dictionary d = strict(write("dictionary", RFC_BASE));
            AttributeDef status = d.attribute(40);
            assertThat(status.name()).isEqualTo("Acct-Status-Type");
            assertThat(status.type()).isEqualTo(DataType.UINT32);
            assertThat(status.value("stop")).isEqualTo(2L);
            assertThat(status.valueName(1)).isEqualTo("Start");
            assertThat(d.find("acct-status-type")).isSameAs(status);
        }

        @Test
        void commentsAndBlankLinesAreIgnored() throws IOException {
            Dictionary d = strict(write("dictionary", "# header", "", "ATTRIBUTE   User-Name\t1\tstring   # trailing"));
            assertThat(d.attribute(1).name()).isEqualTo("User-Name");
        }

        @Test
        void hexNumbersAndValues() throws IOException {
            Dictionary d = strict(write("dictionary", "ATTRIBUTE Foo 0x1a0 integer", "VALUE Foo Bar 0x10"));
            assertThat(d.find("Foo").number()).isEqualTo(0x1a0);
            assertThat(d.find("Foo").value("Bar")).isEqualTo(16L);
        }

        @Test
        void flagsAreParsed() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "ATTRIBUTE User-Password 2 string encrypt=User-Password",
                    "ATTRIBUTE Tunnel-Type 64 uint32 has_tag",
                    "ATTRIBUTE Tunnel-Password 69 string has_tag,encrypt=2",
                    "ATTRIBUTE EAP-Message 79 octets concat",
                    "ATTRIBUTE Counter 200 uint64 counter"));
            assertThat(d.attribute(2).encrypt()).isEqualTo("User-Password");
            assertThat(d.attribute(64).hasTag()).isTrue();
            assertThat(d.attribute(69).hasTag()).isTrue();
            assertThat(d.attribute(69).encrypt()).isEqualTo("Tunnel-Password");
            assertThat(d.attribute(79).concat()).isTrue();
            assertThat(d.attribute(200).options()).containsKey("counter");
        }

        @Test
        void fixedLengthTypes() throws IOException {
            Dictionary d = strict(write("dictionary", "ATTRIBUTE Foo 1 octets[16]"));
            assertThat(d.attribute(1).type()).isEqualTo(DataType.OCTETS);
            assertThat(d.attribute(1).fixedLength()).isEqualTo(16);
        }

        @Test
        void dottedAndRelativeNumbers() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "ATTRIBUTE Extended-Attribute-1 241 tlv extended",
                    "ATTRIBUTE Frag-Status 241.1 uint32",
                    "ATTRIBUTE Container 241.9 tlv",
                    "ATTRIBUTE Child-A .1 tlv",
                    "ATTRIBUTE Child-B .2 string"));
            assertThat(d.find("Frag-Status").oid()).isEqualTo("241.1");
            // relative numbers stay relative to the last absolutely numbered structural attribute
            assertThat(d.find("Child-A").oid()).isEqualTo("241.9.1");
            assertThat(d.find("Child-B").oid()).isEqualTo("241.9.2");
            assertThat(d.find("Extended-Attribute-1.Container.Child-B")).isSameAs(d.find("Child-B"));
        }

        @Test
        void defineAndBeginBlock() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "DEFINE mib-2 tlv internal",
                    "BEGIN mib-2",
                    "ATTRIBUTE Counter 1 uint32",
                    "END mib-2"));
            AttributeDef mib = d.find("mib-2");
            assertThat(mib.number()).isEqualTo(AttributeDef.NO_NUMBER);
            assertThat(mib.internal()).isTrue();
            assertThat(mib.child(1).name()).isEqualTo("Counter");
        }

        @Test
        void structMembersUnionsAndMemberValues() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "ATTRIBUTE Location 127 struct",
                    "MEMBER Index uint16",
                    "MEMBER Code uint8 key",
                    "VALUE Code Civic 0",
                    "MEMBER Flags bit[3]",
                    "MEMBER Data union key=Code",
                    "BEGIN Location.Data",
                    "ATTRIBUTE Civic 0 struct",
                    "MEMBER Country octets[2]",
                    "END Location.Data"));
            AttributeDef location = d.attribute(127);
            assertThat(location.members())
                    .extracting(AttributeDef.MemberDef::name)
                    .containsExactly("Index", "Code", "Flags", "Data");
            assertThat(location.members().get(1).key()).isTrue();
            assertThat(location.members().get(2).fixedLength()).isEqualTo(3);
            assertThat(location.child("Code").value("Civic")).isEqualTo(0L);
            assertThat(d.find("Location.Data.Civic").members()).hasSize(1);
        }

        @Test
        void flagsInternalAppliesToRestOfFile() throws IOException {
            Dictionary d = strict(
                    write("dictionary", "ATTRIBUTE Wire 1 string", "FLAGS internal", "ATTRIBUTE Local 1000 uint32"));
            assertThat(d.attribute(1).internal()).isFalse();
            assertThat(d.attribute(1000).internal()).isTrue();
        }

        @Test
        void otherProtocolsAreSkipped() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "BEGIN PROTOCOL DHCPv4 2",
                    "ATTRIBUTE Subnet-Mask 1 ipaddr",
                    "END-PROTOCOL DHCPv4",
                    "BEGIN PROTOCOL RADIUS 1 verify=lib",
                    "ATTRIBUTE User-Name 1 string",
                    "END-PROTOCOL RADIUS"));
            assertThat(d.attribute(1).name()).isEqualTo("User-Name");
            assertThat(d.find("Subnet-Mask")).isNull();
        }

        @Test
        void keywordsAreCaseInsensitive() throws IOException {
            Dictionary d = strict(write("dictionary", "Attribute User-Name 1 string"));
            assertThat(d.attribute(1)).isNotNull();
        }
    }

    @Nested
    class Vendors {

        @Test
        void v4VendorBlock() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "ATTRIBUTE Vendor-Specific 26 vsa",
                    "VENDOR Cisco 9",
                    "BEGIN-VENDOR Cisco",
                    "ATTRIBUTE AVPair 1 string",
                    "END-VENDOR Cisco",
                    "ALIAS Cisco Vendor-Specific.Cisco"));
            AttributeDef avpair = d.vendorAttribute(9, 1);
            assertThat(avpair.name()).isEqualTo("AVPair");
            assertThat(avpair.vendorId()).isEqualTo(9);
            assertThat(avpair.path()).isEqualTo("Vendor-Specific.Cisco.AVPair");
            assertThat(avpair.oid()).isEqualTo("26.9.1");
            assertThat(d.find("Cisco.AVPair")).isSameAs(avpair);
        }

        @Test
        void vendorFormats() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "VENDOR USR 429 format=4,0",
                    "VENDOR Lucent 4846 format=2,1",
                    "VENDOR WiMAX 24757 format=1,1,c"));
            assertThat(d.vendor(429)).isEqualTo(new VendorDef("USR", 429, 4, 0, false));
            assertThat(d.vendor("lucent").typeLength()).isEqualTo(2);
            assertThat(d.vendor(24757).continuation()).isTrue();
            assertThat(d.vendor(24757).isStandardFormat()).isFalse();
        }

        @Test
        void invalidVendorFormatFails() throws IOException {
            Path file = write("dictionary", "VENDOR Bad 1 format=3,1");
            assertThatThrownBy(() -> strict(file))
                    .isInstanceOf(DictionaryException.class)
                    .hasMessageContaining("dictionary:1")
                    .hasMessageContaining("invalid vendor type length 3");
        }

        @Test
        void vendorParentForExtendedVsa() throws IOException {
            Dictionary d = strict(write(
                    "dictionary",
                    "ATTRIBUTE Extended-Attribute-5 245 tlv long_extended",
                    "ATTRIBUTE Vendor-Specific .26 vsa",
                    "VENDOR FreeRADIUS 11344",
                    "BEGIN-VENDOR FreeRADIUS parent=.Extended-Attribute-5.Vendor-Specific",
                    "ATTRIBUTE Proxied-To 1 ipaddr",
                    "END-VENDOR FreeRADIUS"));
            assertThat(d.find("Proxied-To").oid()).isEqualTo("245.26.11344.1");
            assertThat(d.vendorAttribute(11344, 1)).isNull(); // not inside RFC 2865 attribute 26
        }

        @Test
        void attributeDirectlyUnderVsaIsRejected() throws IOException {
            Path file = write("dictionary", "ATTRIBUTE Vendor-Specific 26 vsa", "ATTRIBUTE Wrong 26.1 string");
            assertThatThrownBy(() -> strict(file)).hasMessageContaining("BEGIN-VENDOR");
        }
    }

    @Nested
    class V3OperatorFiles {

        @Test
        void typicalV32VendorFileLoadsLeniently() throws IOException {
            Path file = write(
                    "dictionary.acme",
                    "# FreeRADIUS v3.2 style",
                    "VENDOR       Acme        99999",
                    "BEGIN-VENDOR Acme",
                    "ATTRIBUTE    Acme-Session-Class   1   string",
                    "ATTRIBUTE    Acme-Rate            2   integer",
                    "ATTRIBUTE    Acme-Secret          3   string   encrypt=1",
                    "ATTRIBUTE    Acme-Tunnel          4   integer  has_tag",
                    "ATTRIBUTE    Acme-Counter         5   integer64",
                    "ATTRIBUTE    Acme-Addr            6   ipaddr",
                    "VALUE        Acme-Rate            Gold   3",
                    "BEGIN-TLV    Acme-Rate",
                    "END-TLV      Acme-Rate",
                    "END-VENDOR   Acme",
                    "ATTRIBUTE    Acme-Old-Style       7   string   Acme");
            Dictionary d = lenient(file);
            assertThat(d.vendorAttribute(99999, 1).name()).isEqualTo("Acme-Session-Class");
            assertThat(d.find("Acme-Rate").value("Gold")).isEqualTo(3L);
            assertThat(d.find("Acme-Secret").encrypt()).isEqualTo("User-Password");
            assertThat(d.find("Acme-Counter").type()).isEqualTo(DataType.UINT64);
            assertThat(d.vendorAttribute(99999, 7).name()).isEqualTo("Acme-Old-Style");
            // BEGIN-TLV on a non-TLV attribute is skipped with a warning in lenient mode
            assertThat(d.warnings()).anyMatch(w -> w.contains("BEGIN-TLV"));
        }

        @Test
        void compatibleRedefinitionBecomesAlias() throws IOException {
            Path base = write(
                    "base",
                    "ATTRIBUTE Vendor-Specific 26 vsa",
                    "VENDOR Cisco 9",
                    "BEGIN-VENDOR Cisco",
                    "ATTRIBUTE AVPair 1 string",
                    "END-VENDOR Cisco");
            Path operator = write(
                    "dictionary.d/dictionary.cisco",
                    "VENDOR Cisco 9",
                    "BEGIN-VENDOR Cisco",
                    "ATTRIBUTE Cisco-AVPair 1 string",
                    "END-VENDOR Cisco");
            Dictionary d = DictionaryLoader.builder()
                    .add(DictionarySource.file(base), ParseMode.STRICT)
                    .addDirectory(operator.getParent(), ParseMode.LENIENT)
                    .load();
            AttributeDef avpair = d.vendorAttribute(9, 1);
            assertThat(avpair.name()).isEqualTo("AVPair");
            assertThat(avpair.alternateNames()).containsExactly("Cisco-AVPair");
            assertThat(d.find("Cisco-AVPair")).isSameAs(avpair);
        }
    }

    @Nested
    class Overrides {

        @Test
        void typeChangeFailsInStrictMode() throws IOException {
            Path file = write("dictionary", "ATTRIBUTE Foo 1 string", "ATTRIBUTE Bar 1 integer");
            assertThatThrownBy(() -> strict(file))
                    .isInstanceOf(DictionaryException.class)
                    .hasMessageContaining("dictionary:2")
                    .hasMessageContaining("different type");
        }

        @Test
        void typeChangeOverridesInLenientModeWithWarning() throws IOException {
            Dictionary d = lenient(write("dictionary", "ATTRIBUTE Foo 1 string", "ATTRIBUTE Bar 1 integer"));
            assertThat(d.attribute(1).name()).isEqualTo("Bar");
            assertThat(d.attribute(1).type()).isEqualTo(DataType.UINT32);
            assertThat(d.warnings()).singleElement().asString().contains("overrides");
        }

        @Test
        void directoryFilesLoadInNameOrderAfterBundled() throws IOException {
            write("d/20-second", "ATTRIBUTE Foo 1000 integer");
            write("d/10-first", "ATTRIBUTE Foo 1000 string");
            write("d/.hidden", "garbage that would fail");
            Dictionary d = DictionaryLoader.builder()
                    .addDirectory(dir.resolve("d"), ParseMode.LENIENT)
                    .load();
            assertThat(d.attribute(1000).type()).isEqualTo(DataType.UINT32);
            assertThat(d.loadedFiles()).hasSize(2);
        }

        @Test
        void missingDirectoryIsAWarning() {
            Dictionary d = DictionaryLoader.builder()
                    .addDirectory(dir.resolve("does-not-exist"))
                    .load();
            assertThat(d.warnings()).singleElement().asString().contains("not found");
        }

        @Test
        void bundledPlusOperatorDirectory() throws IOException {
            write(
                    "ops/dictionary.local",
                    "VENDOR Local 65000",
                    "BEGIN-VENDOR Local",
                    "ATTRIBUTE Local-Tag 1 string",
                    "END-VENDOR Local");
            Dictionary d = DictionaryLoader.builder()
                    .addBundledFreeRadius(ParseMode.STRICT)
                    .addDirectory(dir.resolve("ops"), ParseMode.LENIENT)
                    .load();
            assertThat(d.vendorAttribute(65000, 1).name()).isEqualTo("Local-Tag");
            assertThat(d.vendorAttribute(9, 1).name()).isEqualTo("AVPair");
        }
    }

    @Nested
    class Includes {

        @Test
        void relativeIncludes() throws IOException {
            write("sub/dictionary.rfc", RFC_BASE);
            Dictionary d = strict(write("dictionary", "$INCLUDE sub/dictionary.rfc"));
            assertThat(d.attribute(40)).isNotNull();
            assertThat(d.loadedFiles()).hasSize(2);
        }

        @Test
        void missingIncludeFails() throws IOException {
            Path file = write("dictionary", "ATTRIBUTE User-Name 1 string", "$INCLUDE dictionary.missing");
            assertThatThrownBy(() -> strict(file))
                    .hasMessageContaining("dictionary:2")
                    .hasMessageContaining("not found");
        }

        @Test
        void optionalIncludeMayBeMissing() throws IOException {
            Dictionary d = strict(write("dictionary", "$INCLUDE- dictionary.missing", "ATTRIBUTE User-Name 1 string"));
            assertThat(d.attribute(1)).isNotNull();
        }

        @Test
        void includeCycleFails() throws IOException {
            write("a", "$INCLUDE b");
            write("b", "$INCLUDE a");
            assertThatThrownBy(() -> strict(dir.resolve("a")))
                    .isInstanceOf(DictionaryException.class)
                    .hasMessageContaining("cycle");
        }
    }

    @Nested
    class Errors {

        @Test
        void unknownKeywordStrictFailsWithLocation() throws IOException {
            Path file = write("dictionary", "ATTRIBUTE User-Name 1 string", "", "FROBNICATE x");
            assertThatThrownBy(() -> strict(file))
                    .isInstanceOf(DictionaryException.class)
                    .hasMessageContaining("dictionary:3")
                    .hasMessageContaining("unknown keyword FROBNICATE");
        }

        @Test
        void unknownKeywordLenientWarns() throws IOException {
            Dictionary d = lenient(write("dictionary", "FROBNICATE x", "ATTRIBUTE User-Name 1 string"));
            assertThat(d.attribute(1)).isNotNull();
            assertThat(d.warnings()).singleElement().asString().contains("dictionary:1");
        }

        @Test
        void unknownTypeAndFlag() throws IOException {
            assertThatThrownBy(() -> strict(write("t1", "ATTRIBUTE Foo 1 quaternion")))
                    .hasMessageContaining("unknown data type quaternion");
            assertThatThrownBy(() -> strict(write("t2", "ATTRIBUTE Foo 1 string sparkly")))
                    .hasMessageContaining("unknown flag sparkly");
        }

        @Test
        void unresolvedValueAndAlias() throws IOException {
            assertThatThrownBy(() -> strict(write("v", "VALUE Nope Foo 1")))
                    .hasMessageContaining("undefined attribute Nope");
            assertThatThrownBy(() -> strict(write("a", "ALIAS Foo Nope"))).hasMessageContaining("target not found");
        }

        @Test
        void valueBeforeAttributeIsResolvedLater() throws IOException {
            Dictionary d = strict(write("dictionary", "VALUE Foo Bar 7", "ATTRIBUTE Foo 1 integer"));
            assertThat(d.attribute(1).value("Bar")).isEqualTo(7L);
        }

        @Test
        void unbalancedBlocks() throws IOException {
            assertThatThrownBy(() -> strict(write("u1", "VENDOR X 1", "BEGIN-VENDOR X")))
                    .hasMessageContaining("unterminated block");
            assertThatThrownBy(() -> strict(write("u2", "END-VENDOR X"))).hasMessageContaining("without BEGIN-VENDOR");
            assertThatThrownBy(() -> strict(write("u3", "BEGIN-VENDOR Unknown")))
                    .hasMessageContaining("undeclared vendor");
        }

        @Test
        void relativeNumberWithoutParent() throws IOException {
            assertThatThrownBy(() -> strict(write("r", "ATTRIBUTE Foo .1 string")))
                    .hasMessageContaining("relative number");
        }
    }
}
