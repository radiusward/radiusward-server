/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The test suite of RFC 1320 §A.5. */
class Md4Test {

    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            value = {
                "''|31d6cfe0d16ae931b73c59d7e0c089c0",
                "a|bde52cb31de33e46245e05fbdbd6fb24",
                "abc|a448017aaf21d8525fc10ae87aa6729d",
                "message digest|d9130a8164549fe818874806e1c7014b",
                "abcdefghijklmnopqrstuvwxyz|d79e1c308aa5bbcdeea8ed63df412da9",
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789|043f8582f241db351ce627e153e7f0e4",
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                        + "|e33b4ddc9c38f2199c3e7b164fcc0536"
            })
    void rfc1320Vectors(String message, String digest) {
        assertThat(HexFormat.of().formatHex(Md4.digest(message.getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo(digest);
    }
}
