/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class RadiusPacketEncoderTest {

    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();

    @Test
    void encodesHeaderAndAttributes() {
        int length = encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, 200)
                .uint32(40, 2)
                .uint64(200, 0x0102030405060708L)
                .attribute(44, new byte[] {'x'})
                .attribute(44, new UnsafeBuffer(new byte[] {9, 'y', 9}), 1, 1)
                .vendorUint32(2011, 3, 1_000_000)
                .vendorAttribute(9, 1, new UnsafeBuffer(new byte[] {'a'}), 0, 1)
                .finish();
        assertThat(length).isEqualTo(encoder.length());
        assertThat(Packets.hex(java.util.Arrays.copyOf(buffer.byteArray(), length)))
                .isEqualTo("04c8" + String.format("%04x", length) + "00".repeat(16)
                        + "280600000002" + "c80a0102030405060708" + "2c0378" + "2c0379"
                        + "1a0c000007db0306000f4240" + "1a090000000901036" + "1");
        RadiusPacket packet = Packets.wrap(java.util.Arrays.copyOf(buffer.byteArray(), length));
        assertThat(packet.isValid()).isTrue();
        assertThat(packet.identifier()).isEqualTo(200);
    }

    @Test
    void authenticatorAndRawCopy() {
        byte[] auth = Packets.hex("000102030405060708090a0b0c0d0e0f");
        byte[] source = Packets.hex("21 05 616263");
        int length = encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_RESPONSE, 1)
                .authenticator(auth)
                .rawAttribute(new UnsafeBuffer(source), 0)
                .finish();
        assertThat(length).isEqualTo(25);
        assertThat(buffer.getByte(4)).isEqualTo((byte) 0);
        assertThat(buffer.getByte(19)).isEqualTo((byte) 15);
        encoder.wrap(buffer, 0).header(5, 1).authenticator(new UnsafeBuffer(auth), 0);
        assertThat(buffer.getByte(5)).isEqualTo((byte) 1);
        assertThatThrownBy(() -> encoder.authenticator(new byte[3])).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsOversizedValues() {
        encoder.wrap(buffer, 0).header(4, 1);
        assertThatThrownBy(() -> encoder.attribute(1, new byte[254])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> encoder.vendorAttribute(9, 1, new byte[248]))
                .isInstanceOf(IllegalArgumentException.class);
        encoder.vendorAttribute(9, 1, new byte[247]); // 6 + 2 + 247 = 255 is the maximum
    }

    @Test
    void rejectsPacketsOver4096Bytes() {
        encoder.wrap(buffer, 0).header(4, 1);
        for (int i = 0; i < 15; i++) {
            encoder.attribute(1, new byte[253]);
        }
        assertThat(encoder.length()).isEqualTo(20 + 15 * 255);
        assertThatThrownBy(() -> encoder.attribute(1, new byte[253])).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void respectsBufferCapacity() {
        UnsafeBuffer small = new UnsafeBuffer(new byte[30]);
        encoder.wrap(small, 0).header(4, 1);
        assertThatThrownBy(() -> encoder.attribute(1, new byte[10])).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> encoder.wrap(new UnsafeBuffer(new byte[10]), 0).header(4, 1))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void stringConvenience() {
        int length = encoder.wrap(buffer, 0)
                .header(4, 1)
                .attribute(1, "é")
                .vendorAttribute(9, 1, "k=v")
                .ipv4(4, 0x7F000001L)
                .finish();
        assertThat(length).isEqualTo(20 + 4 + 11 + 6);
    }
}
