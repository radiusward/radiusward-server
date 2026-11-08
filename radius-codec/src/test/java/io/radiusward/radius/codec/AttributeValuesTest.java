/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;

import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class AttributeValuesTest {

    private final UnsafeBuffer buffer = new UnsafeBuffer(Packets.hex("ff fe dc ba 98 76 54 32 c0 a8 01 03 61 62"));

    @Test
    void unsignedReaders() {
        assertThat(AttributeValues.uint8(buffer, 0, 1)).isEqualTo(0xff);
        assertThat(AttributeValues.uint16(buffer, 0, 2)).isEqualTo(0xfffe);
        assertThat(AttributeValues.uint32(buffer, 0, 4)).isEqualTo(0xfffedcbaL);
        assertThat(AttributeValues.uint64(buffer, 0, 8)).isEqualTo(0xfffedcba98765432L);
        assertThat(AttributeValues.int32(buffer, 0, 4)).isEqualTo((long) 0xfffedcba);
    }

    @Test
    void wrongLengthsAreInvalid() {
        assertThat(AttributeValues.uint8(buffer, 0, 2)).isEqualTo(AttributeValues.INVALID);
        assertThat(AttributeValues.uint16(buffer, 0, 3)).isEqualTo(AttributeValues.INVALID);
        assertThat(AttributeValues.uint32(buffer, 0, 3)).isEqualTo(AttributeValues.INVALID);
        assertThat(AttributeValues.uint64(buffer, 0, 4)).isEqualTo(AttributeValues.INVALID);
        assertThat(AttributeValues.int32(buffer, 0, 2)).isEqualTo(Long.MIN_VALUE);
        assertThat(AttributeValues.ipv4(buffer, 8, 3)).isEqualTo(AttributeValues.INVALID);
    }

    @Test
    void addressesStringsAndHex() {
        assertThat(AttributeValues.ipv4String(AttributeValues.ipv4(buffer, 8, 4)))
                .isEqualTo("192.168.1.3");
        assertThat(AttributeValues.string(buffer, 12, 2)).isEqualTo("ab");
        assertThat(AttributeValues.hex(buffer, 10, 4)).isEqualTo("01036162");
        assertThat(AttributeValues.equals(buffer, 12, 2, new byte[] {'a', 'b'})).isTrue();
        assertThat(AttributeValues.equals(buffer, 12, 2, new byte[] {'a', 'c'})).isFalse();
        assertThat(AttributeValues.equals(buffer, 12, 1, new byte[] {'a', 'b'})).isFalse();
    }

    @Test
    void octetCountersWithGigawords() {
        assertThat(AttributeValues.octets64(5, 0)).isEqualTo(5);
        assertThat(AttributeValues.octets64(0xFFFF_FFFFL, 1)).isEqualTo(0x1_FFFF_FFFFL);
        assertThat(AttributeValues.octets64(-1, 2)).isEqualTo(0x2_FFFF_FFFFL);
    }
}
