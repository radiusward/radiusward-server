/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class SimMessageTest {

    @Test
    void whatTheBuilderWritesParsesBack() {
        byte[] rand = new byte[16];
        rand[0] = 9;
        SimMessage.Builder b = new SimMessage.Builder(1)
                .reserved(SimMessage.AT_RAND, rand)
                .lengthPrefixed(SimMessage.AT_IDENTITY, "0262011000000001@wlan".getBytes(StandardCharsets.US_ASCII))
                .uint16(SimMessage.AT_COUNTER, 7)
                .mac();
        byte[] data = b.build();
        assertThat(data.length % 4)
                .as("attributes in 4-byte units after the 3-byte header")
                .isEqualTo(3);
        SimMessage m = SimMessage.parse(data);
        assertThat(m).isNotNull();
        assertThat(m.subtype()).isEqualTo(1);
        assertThat(m.get(SimMessage.AT_RAND)).startsWith(0, 0, 9);
        assertThat(new String(SimMessage.lengthPrefixed(m.get(SimMessage.AT_IDENTITY)), StandardCharsets.US_ASCII))
                .isEqualTo("0262011000000001@wlan");
        assertThat(m.get(SimMessage.AT_COUNTER)).containsExactly(0, 7);
        assertThat(m.has(SimMessage.AT_MAC)).isTrue();
        assertThat(m.macOffset()).isEqualTo(b.macOffset());
        assertThat(m.has(SimMessage.AT_NONCE_S)).isFalse();
    }

    @Test
    void malformedMessagesAreRefused() {
        assertThat(SimMessage.parse(new byte[2])).as("too short").isNull();
        assertThat(SimMessage.parse(new byte[] {1, 0, 0, (byte) SimMessage.AT_COUNTER, 0}))
                .as("length 0")
                .isNull();
        assertThat(SimMessage.parse(new byte[] {1, 0, 0, (byte) SimMessage.AT_COUNTER, 2, 0, 0}))
                .as("truncated")
                .isNull();
        byte[] twice = new SimMessage.Builder(1)
                .uint16(SimMessage.AT_COUNTER, 1)
                .uint16(SimMessage.AT_COUNTER, 2)
                .build();
        assertThat(SimMessage.parse(twice)).as("an attribute twice").isNull();
        assertThat(SimMessage.parse(
                        new SimMessage.Builder(1).add(99, new byte[2]).build()))
                .as("an unknown attribute below 128 cannot be skipped")
                .isNull();
        assertThat(SimMessage.parse(
                        new SimMessage.Builder(1).add(200, new byte[2]).build()))
                .as("128 and above are skipped")
                .isNotNull();
        assertThat(SimMessage.lengthPrefixed(null)).isNull();
    }

    @Test
    void theMacIsComputedOverThePacketWithItZeroed() {
        SimMessage.Builder b = new SimMessage.Builder(11).mac();
        byte[] data = b.build();
        data[b.macOffset()] = 42;
        byte[] packet = SimMessage.packet(1, 5, EapPacket.TYPE_SIM, data, b.macOffset());
        assertThat(packet[4]).isEqualTo((byte) EapPacket.TYPE_SIM);
        assertThat(packet[5 + b.macOffset()]).as("zeroed").isZero();
        assertThat(packet).hasSize(5 + data.length);
    }

    @Test
    void gsmTripletsComeFromMilenage() {
        byte[] ki = new byte[16];
        byte[] opc = new byte[16];
        byte[][] triplet = SimVectors.gsm(ki, opc, new byte[16]);
        assertThat(triplet).hasNumberOfRows(2);
        assertThat(triplet[0]).as("SRES").hasSize(4);
        assertThat(triplet[1]).as("Kc").hasSize(8);
    }
}
