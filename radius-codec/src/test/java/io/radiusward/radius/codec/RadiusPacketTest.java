/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.hex;
import static io.radiusward.radius.codec.Packets.wrap;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** Framing rules of RFC 2865 §3 and RFC 3579 §3.2. */
class RadiusPacketTest {

    /** RFC 2865 §7.1 Access-Request. */
    static final String RFC2865_ACCESS_REQUEST = "01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb 98 f4 22 7a"
            + "01 06 6e 65 6d 6f 02 12 0d be 70 8d 93 d4 13 ce 31 96 e4 3f 78 2a 0a ee"
            + "04 06 c0 a8 01 10 05 06 00 00 00 03";

    @Test
    void headerFields() {
        RadiusPacket packet = wrap(hex(RFC2865_ACCESS_REQUEST));
        assertThat(packet.status()).isEqualTo(DecodeStatus.OK);
        assertThat(packet.isValid()).isTrue();
        assertThat(packet.code()).isEqualTo(RadiusCode.ACCESS_REQUEST);
        assertThat(packet.identifier()).isZero();
        assertThat(packet.length()).isEqualTo(56);
        assertThat(packet.attributesOffset()).isEqualTo(20);
        assertThat(packet.attributesEnd()).isEqualTo(56);
        assertThat(packet.findAttribute(4)).isEqualTo(44);
        assertThat(packet.findAttribute(99)).isEqualTo(-1);
        assertThat(packet.hasMessageAuthenticator()).isFalse();
    }

    @Test
    void worksAtNonZeroOffset() {
        byte[] packet = hex(RFC2865_ACCESS_REQUEST);
        byte[] shifted = new byte[packet.length + 7];
        System.arraycopy(packet, 0, shifted, 7, packet.length);
        RadiusPacket view = new RadiusPacket();
        assertThat(view.wrap(new UnsafeBuffer(shifted), 7, packet.length)).isEqualTo(DecodeStatus.OK);
        assertThat(view.findAttribute(4)).isEqualTo(7 + 44);
    }

    @Test
    void tooShort() {
        assertThat(wrap(new byte[19]).status()).isEqualTo(DecodeStatus.TOO_SHORT);
        assertThat(wrap(new byte[0]).status()).isEqualTo(DecodeStatus.TOO_SHORT);
    }

    @Test
    void lengthFieldOutOfRange() {
        byte[] packet = hex(RFC2865_ACCESS_REQUEST);
        packet[2] = 0;
        packet[3] = 19;
        assertThat(wrap(packet).status()).isEqualTo(DecodeStatus.INVALID_LENGTH);

        byte[] big = new byte[5000];
        big[2] = (byte) (4097 >> 8);
        big[3] = (byte) (4097 & 0xFF);
        assertThat(wrap(big).status()).isEqualTo(DecodeStatus.INVALID_LENGTH);
    }

    @Test
    void lengthFieldLargerThanDatagramIsTruncated() {
        byte[] packet = hex(RFC2865_ACCESS_REQUEST);
        assertThat(wrap(Arrays.copyOf(packet, packet.length - 1)).status()).isEqualTo(DecodeStatus.TRUNCATED);
    }

    @Test
    void trailingBytesBeyondLengthAreIgnored() {
        byte[] packet = hex(RFC2865_ACCESS_REQUEST);
        RadiusPacket view = wrap(Arrays.copyOf(packet, packet.length + 10));
        assertThat(view.status()).isEqualTo(DecodeStatus.OK);
        assertThat(view.length()).isEqualTo(56);
    }

    @Test
    void attributeLengthBelowTwo() {
        byte[] packet = hex(RFC2865_ACCESS_REQUEST);
        packet[21] = 1; // User-Name length
        assertThat(wrap(packet).status()).isEqualTo(DecodeStatus.MALFORMED_ATTRIBUTE);
    }

    @Test
    void attributeRunningPastEnd() {
        byte[] packet = hex(RFC2865_ACCESS_REQUEST);
        packet[51] = 7; // last attribute claims one byte more than there is
        assertThat(wrap(packet).status()).isEqualTo(DecodeStatus.MALFORMED_ATTRIBUTE);
    }

    @Test
    void singleDanglingByte() {
        byte[] packet = hex("04 01 00 15 00000000000000000000000000000000 01");
        assertThat(wrap(packet).status()).isEqualTo(DecodeStatus.MALFORMED_ATTRIBUTE);
    }

    @Test
    void messageAuthenticatorMustBe18Bytes() {
        byte[] packet = hex("04 01 00 18 00000000000000000000000000000000 50 04 00 00");
        assertThat(wrap(packet).status()).isEqualTo(DecodeStatus.MALFORMED_MESSAGE_AUTHENTICATOR);
    }

    @Test
    void messageAuthenticatorIsLocated() {
        RadiusPacket packet = wrap(Packets.accountingRequest(7, true));
        assertThat(packet.hasMessageAuthenticator()).isTrue();
        assertThat(packet.buffer().getByte(packet.messageAuthenticatorOffset())).isEqualTo((byte) 80);
    }

    @Test
    void rewrapResetsState() {
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(new UnsafeBuffer(Packets.accountingRequest(1, true)), 0, Packets.accountingRequest(1, true).length);
        byte[] plain = Packets.accountingRequest(2, false);
        packet.wrap(new UnsafeBuffer(plain), 0, plain.length);
        assertThat(packet.hasMessageAuthenticator()).isFalse();
        assertThat(packet.identifier()).isEqualTo(2);
        packet.wrap(new UnsafeBuffer(new byte[3]), 0, 3);
        assertThat(packet.isValid()).isFalse();
        assertThat(packet.findAttribute(1)).isEqualTo(-1);
    }

    @Test
    void codeNames() {
        assertThat(RadiusCode.name(RadiusCode.ACCOUNTING_REQUEST)).isEqualTo("Accounting-Request");
        assertThat(RadiusCode.name(RadiusCode.COA_NAK)).isEqualTo("CoA-NAK");
        assertThat(RadiusCode.name(200)).isEqualTo("Unknown-200");
        assertThat(RadiusCode.hasComputedRequestAuthenticator(RadiusCode.ACCOUNTING_REQUEST))
                .isTrue();
        assertThat(RadiusCode.hasComputedRequestAuthenticator(RadiusCode.ACCESS_REQUEST))
                .isFalse();
        for (int code : new int[] {1, 2, 3, 4, 5, 11, 12, 13, 40, 41, 42, 43, 44, 45}) {
            assertThat(RadiusCode.name(code)).doesNotStartWith("Unknown");
        }
        assertThat(hex(new byte[] {1})).isEqualTo("01");
    }
}
