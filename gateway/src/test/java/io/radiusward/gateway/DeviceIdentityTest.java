/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class DeviceIdentityTest {

    private static String mac(String value) {
        UnsafeBuffer in = new UnsafeBuffer(value.getBytes(StandardCharsets.US_ASCII));
        UnsafeBuffer out = new UnsafeBuffer(new byte[16]);
        int n = DeviceIdentity.mac(in, 0, in.capacity(), out);
        return n < 0 ? null : out.getStringWithoutLengthAscii(0, n);
    }

    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            value = {
                "AA-BB-CC-DD-EE-FF:Guest WiFi | aabbccddeeff",
                "aa:bb:cc:dd:ee:ff | aabbccddeeff",
                "aa:bb:cc:dd:ee:ff:Corp | aabbccddeeff",
                "aabb.ccdd.eeff | aabbccddeeff",
                "AABBCCDDEEFF | aabbccddeeff",
                "AABBCCDDEEFF:ssid | aabbccddeeff",
                "0A-1b-2C-3d-4E-5f | 0a1b2c3d4e5f"
            })
    void macAddressesAreNormalised(String value, String expected) {
        assertThat(mac(value)).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({"ap-lobby", "AABBCCDDEE", "AABBCCDDEEFF00", "AABBCCDDEEFF-x", "aa:bb:cc:dd:ee:gg", "''"})
    void otherValuesAreNotMacs(String value) {
        assertThat(mac(value)).isNull();
    }

    @ParameterizedTest
    @CsvSource({"167772161, 10.0.0.1", "3232235777, 192.168.1.1", "0, 0.0.0.0", "4294967295, 255.255.255.255"})
    void nasIpAddressIsDottedDecimal(long address, String expected) {
        UnsafeBuffer out = new UnsafeBuffer(new byte[16]);
        int n = DeviceIdentity.ipv4(address, out);
        assertThat(out.getStringWithoutLengthAscii(0, n)).isEqualTo(expected);
    }
}
