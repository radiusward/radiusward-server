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

/** Vectors from an independent reference implementation (and the published "quick brown fox" value). */
class Murmur3Test {

    @ParameterizedTest
    @CsvSource({
        "'The quick brown fox jumps over the lazy dog', -2068352364225029268, 8809951995912426311",
        "'', 0, 0",
        "a, -8839064797231613815, -1822486391929534118",
        "hello, -3758069500696749310, 6565844092913065241",
        "0123456789abcdef, 5467490433528156583, -8663980805763692326",
        "0123456789abcdefg, -8200385122730116642, 576729866477728494",
        "00000A1B, 1386220539264016358, 9195826111427913417",
    })
    void referenceVectors(String input, long hi, long lo) {
        byte[] bytes = input.getBytes(StandardCharsets.US_ASCII);
        byte[] padded = new byte[bytes.length + 9];
        System.arraycopy(bytes, 0, padded, 3, bytes.length); // non-zero offset
        Murmur3 murmur = new Murmur3().hash(new UnsafeBuffer(padded), 3, bytes.length);
        assertThat(murmur.hi()).isEqualTo(hi);
        assertThat(murmur.lo()).isEqualTo(lo);
    }
}
