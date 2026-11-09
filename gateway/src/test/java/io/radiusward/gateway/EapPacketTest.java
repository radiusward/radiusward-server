/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class EapPacketTest {

    static RadiusPacket carrying(EapPacket eap) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[4096]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 1)
                .authenticator(new byte[16]);
        enc.attribute(1, "x");
        eap.writeTo(enc);
        int length = enc.finish();
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(Arrays.copyOf(buffer.byteArray(), length)), 0, length);
        return p;
    }

    @Test
    void roundTripThroughSeveralEapMessageAttributes() {
        byte[] data = new byte[700];
        Arrays.fill(data, (byte) 7);
        EapPacket big = EapPacket.request(42, 13, data);
        RadiusPacket p = carrying(big);
        int attributes = 0;
        for (int pos = p.attributesOffset();
                pos < p.attributesEnd();
                pos += p.buffer().getByte(pos + 1) & 0xFF) {
            if ((p.buffer().getByte(pos) & 0xFF) == 79) {
                attributes++;
            }
        }
        assertThat(attributes).as("705 bytes in 253-byte pieces").isEqualTo(3);
        EapPacket back = EapPacket.from(p);
        assertThat(back.code()).isEqualTo(EapPacket.REQUEST);
        assertThat(back.identifier()).isEqualTo(42);
        assertThat(back.type()).isEqualTo(13);
        assertThat(back.data()).isEqualTo(data);
        EapPacket success = EapPacket.parse(EapPacket.success(9).encode());
        assertThat(success.code()).isEqualTo(EapPacket.SUCCESS);
        assertThat(success.identifier()).isEqualTo(9);
    }

    @Test
    void malformedPacketsAreNull() {
        assertThat(EapPacket.parse(new byte[] {2, 1, 0})).as("too short").isNull();
        assertThat(EapPacket.parse(new byte[] {2, 1, 0, 9, 1}))
                .as("length beyond the data")
                .isNull();
        assertThat(EapPacket.parse(new byte[] {2, 1, 0, 4}))
                .as("a response without a type")
                .isNull();
        assertThat(EapPacket.parse(new byte[] {3, 1, 0, 5, 0}))
                .as("success with data")
                .isNull();
        assertThat(EapPacket.parse(new byte[] {9, 1, 0, 5, 1}))
                .as("unknown code")
                .isNull();
        assertThat(EapPacket.parse(new byte[] {2, 1, 0, 6, 1, 'a'}).data()).containsExactly('a');
    }
}
