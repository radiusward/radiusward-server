/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Set;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class AttributesTest {

    private static final Attributes ATTRIBUTES = new Attributes(DictionaryLoader.loadBundled());

    /** The attribute section of an Accounting-Request built with the codec's encoder. */
    private static byte[] section() {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder().wrap(buffer, 0);
        encoder.header(RadiusCode.ACCOUNTING_REQUEST, 1);
        encoder.attribute(40, new byte[] {0, 0, 0, 3}); // Acct-Status-Type = Interim-Update
        encoder.attribute(1, "alice@example.net".getBytes(StandardCharsets.US_ASCII));
        encoder.attribute(8, new byte[] {100, 64, 0, 10}); // Framed-IP-Address
        encoder.attribute(4, new byte[] {(byte) 192, 0, 2, 1}); // NAS-IP-Address
        encoder.attribute(61, new byte[] {0, 0, 0, 5}); // NAS-Port-Type = Virtual
        encoder.attribute(25, new byte[] {1, 2}); // Class, binary
        encoder.attribute(25, new byte[] {3, 4}); // Class again
        encoder.attribute(49, new byte[] {0, 0, 0, 1}); // Acct-Terminate-Cause = User-Request
        encoder.vendorAttribute(9, 1, "a=1".getBytes(StandardCharsets.US_ASCII)); // Cisco-AVPair
        encoder.vendorAttribute(9, 1, "b=2".getBytes(StandardCharsets.US_ASCII));
        encoder.vendorAttribute(64999, 7, "x".getBytes(StandardCharsets.US_ASCII)); // unknown vendor
        int length = encoder.finish();
        return Arrays.copyOfRange(buffer.byteArray(), RadiusPacket.HEADER_LENGTH, length);
    }

    @Test
    void commonValuesForTypedColumns() {
        Attributes.Common common = ATTRIBUTES.common(section());
        assertThat(common.userName()).isEqualTo("alice@example.net");
        assertThat(common.framedIp()).isEqualTo("100.64.0.10");
        assertThat(common.nasIp()).isEqualTo("192.0.2.1");
        assertThat(common.terminateCause()).isEqualTo(1);
        assertThat(common.callingStationId()).isNull();
        assertThat(ATTRIBUTES.common(null).userName()).isNull();
    }

    @Test
    void canonicalJsonUsesArraysNamesAndBase64() {
        String json = ATTRIBUTES.json(section(), Set.of());
        assertThat(json)
                .startsWith("{\"Acct-Status-Type\":[\"Interim-Update\"]")
                .contains("\"User-Name\":[\"alice@example.net\"]")
                .contains("\"Framed-IP-Address\":[\"100.64.0.10\"]")
                .contains("\"NAS-Port-Type\":[\"Virtual\"]")
                .contains("\"Class\":[{\"base64\":\"AQI=\"},{\"base64\":\"AwQ=\"}]")
                .contains("\"Cisco.AVPair\":[\"a=1\",\"b=2\"]")
                .contains("\"Vendor-64999-Attr-7\":[{\"base64\":\"eA==\"}]");
    }

    @Test
    void residualJsonLeavesOutTypedColumns() {
        String json = ATTRIBUTES.json(section(), Attributes.COMMON);
        assertThat(json)
                .doesNotContain("User-Name")
                .doesNotContain("Acct-Status-Type")
                .contains("NAS-Port-Type");
        assertThat(ATTRIBUTES.json(new byte[0], Set.of())).isNull();
    }
}
