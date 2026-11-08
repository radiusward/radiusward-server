/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.hex;
import static io.radiusward.radius.codec.Packets.wrap;
import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.dictionary.DictionaryLoader;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AttributeCursorTest {

    record Entry(int vendorId, int type, String value) {}

    private static List<Entry> entries(RadiusPacket packet, VendorFormats formats) {
        AttributeCursor cursor = new AttributeCursor(formats).wrap(packet);
        List<Entry> result = new ArrayList<>();
        while (cursor.next()) {
            result.add(new Entry(
                    cursor.vendorId(),
                    cursor.type(),
                    AttributeValues.hex(cursor.buffer(), cursor.valueOffset(), cursor.valueLength())));
        }
        return result;
    }

    private static byte[] packet(String attributesHex) {
        byte[] attributes = hex(attributesHex);
        byte[] packet = new byte[20 + attributes.length];
        packet[0] = RadiusCode.ACCOUNTING_REQUEST;
        packet[2] = (byte) (packet.length >> 8);
        packet[3] = (byte) packet.length;
        System.arraycopy(attributes, 0, packet, 20, attributes.length);
        return packet;
    }

    @Test
    void topLevelAttributes() {
        RadiusPacket p = wrap(packet("28 06 00000001 2c 05 616263"));
        assertThat(entries(p, VendorFormats.ALL_STANDARD))
                .containsExactly(new Entry(0, 40, "00000001"), new Entry(0, 44, "616263"));
    }

    @Test
    void emptyValue() {
        RadiusPacket p = wrap(packet("2c 02"));
        assertThat(entries(p, VendorFormats.ALL_STANDARD)).containsExactly(new Entry(0, 44, ""));
    }

    @Test
    void standardVsaWithSeveralSubAttributes() {
        // 26, len 16, vendor 9, [1, 4, "ab"], [2, 6, 00000005]
        RadiusPacket p = wrap(packet("1a 10 00000009 01 04 6162 02 06 00000005"));
        AttributeCursor cursor = new AttributeCursor().wrap(p);
        assertThat(cursor.next()).isTrue();
        assertThat(cursor.isVendorSpecific()).isTrue();
        assertThat(cursor.vendorId()).isEqualTo(9);
        assertThat(cursor.type()).isEqualTo(1);
        assertThat(cursor.attributeOffset()).isEqualTo(20);
        assertThat(cursor.attributeLength()).isEqualTo(16);
        assertThat(cursor.next()).isTrue();
        assertThat(cursor.type()).isEqualTo(2);
        assertThat(AttributeValues.uint32(cursor.buffer(), cursor.valueOffset(), cursor.valueLength()))
                .isEqualTo(5);
        assertThat(cursor.next()).isFalse();
    }

    @Test
    void vsaFollowedByTopLevel() {
        RadiusPacket p = wrap(packet("1a 0a 00000009 01 04 6162 01 03 78"));
        assertThat(entries(p, VendorFormats.ALL_STANDARD))
                .containsExactly(new Entry(9, 1, "6162"), new Entry(0, 1, "78"));
    }

    @Test
    void malformedVsaContentIsOpaque() {
        // sub-attribute claims length 9 but only 4 bytes remain
        RadiusPacket p = wrap(packet("1a 0a 00000009 01 09 6162"));
        assertThat(entries(p, VendorFormats.ALL_STANDARD)).containsExactly(new Entry(0, 26, "000000090109" + "6162"));
    }

    @Test
    void vsaWithoutContentOrVendorZeroIsOpaque() {
        assertThat(entries(wrap(packet("1a 06 00000009")), VendorFormats.ALL_STANDARD))
                .containsExactly(new Entry(0, 26, "00000009"));
        assertThat(entries(wrap(packet("1a 04 0000")), VendorFormats.ALL_STANDARD))
                .containsExactly(new Entry(0, 26, "0000"));
        assertThat(entries(wrap(packet("1a 09 00000000 01 03 61")), VendorFormats.ALL_STANDARD))
                .containsExactly(new Entry(0, 26, "00000000010361"));
    }

    @Test
    void vendorFormatFourZero() {
        // USR: 4 byte type, no length field: value is the rest of the VSA
        VendorFormats usr = id -> id == 429 ? VendorFormats.pack(4, 0, false) : VendorFormats.STANDARD;
        RadiusPacket p = wrap(packet("1a 0d 000001ad 00009801 616263"));
        assertThat(entries(p, usr)).containsExactly(new Entry(429, 0x9801, "616263"));
    }

    @Test
    void vendorFormatTwoOne() {
        VendorFormats lucent = id -> VendorFormats.pack(2, 1, false);
        RadiusPacket p = wrap(packet("1a 0e 000012ee 0102 05 6162 0103 03"));
        assertThat(entries(p, lucent)).containsExactly(new Entry(4846, 0x102, "6162"), new Entry(4846, 0x103, ""));
    }

    @Test
    void vendorFormatTwoTwo() {
        VendorFormats starent = id -> VendorFormats.pack(2, 2, false);
        RadiusPacket p = wrap(packet("1a 0c 00001fe4 0001 0006 6162"));
        assertThat(entries(p, starent)).containsExactly(new Entry(8164, 1, "6162"));
    }

    @Test
    void vendorFormatWithContinuation() {
        // WiMAX 1,1,c: type, length, continuation flags byte, value
        VendorFormats wimax = id -> VendorFormats.pack(1, 1, true);
        RadiusPacket p = wrap(packet("1a 0b 000060b5 01 05 00 6162"));
        assertThat(entries(p, wimax)).containsExactly(new Entry(24757, 1, "6162"));
    }

    @Test
    void formatsFromDictionary() {
        VendorFormats formats = VendorFormats.from(DictionaryLoader.loadBundled());
        assertThat(formats.format(9)).isEqualTo(VendorFormats.STANDARD);
        assertThat(VendorFormats.typeLength(formats.format(429))).isEqualTo(4);
        assertThat(VendorFormats.lengthLength(formats.format(429))).isZero();
        assertThat(VendorFormats.continuation(formats.format(24757))).isTrue();
        assertThat(formats.format(999_999)).isEqualTo(VendorFormats.STANDARD);
    }

    @Test
    void extendedType() {
        RadiusPacket p = wrap(packet("f1 04 01 00 2c 03 61 f5 05 1a 80 00"));
        AttributeCursor cursor = new AttributeCursor().wrap(p);
        assertThat(cursor.next()).isTrue();
        assertThat(cursor.type()).isEqualTo(241);
        assertThat(cursor.extendedType()).isEqualTo(1);
        assertThat(cursor.next()).isTrue();
        assertThat(cursor.extendedType()).isEqualTo(-1);
        assertThat(cursor.next()).isTrue();
        assertThat(cursor.type()).isEqualTo(245);
        assertThat(cursor.extendedType()).isEqualTo(26);
        assertThat(cursor.next()).isFalse();
    }

    @Test
    void cursorIsReusable() {
        AttributeCursor cursor = new AttributeCursor();
        RadiusPacket first = wrap(packet("1a 0a 00000009 01 04 6162 01 03 78"));
        cursor.wrap(first);
        assertThat(cursor.next()).isTrue(); // stop inside the VSA
        RadiusPacket second = wrap(packet("2c 03 61"));
        cursor.wrap(second);
        assertThat(cursor.next()).isTrue();
        assertThat(cursor.vendorId()).isZero();
        assertThat(cursor.type()).isEqualTo(44);
        assertThat(cursor.next()).isFalse();
    }

    @Test
    void unvalidatedRegionStopsInsteadOfOverrunning() {
        byte[] bytes = hex("01 09 6162");
        AttributeCursor cursor = new AttributeCursor().wrap(new org.agrona.concurrent.UnsafeBuffer(bytes), 0, 4);
        assertThat(cursor.next()).isFalse();
    }
}
