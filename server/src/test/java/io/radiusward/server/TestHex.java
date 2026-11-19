/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import java.util.HexFormat;
import java.util.Locale;

/** Hex in the server's tests, as the MS-CHAP test vectors write it (upper case). */
final class TestHex {

    private TestHex() {}

    static byte[] bytes(String hex) {
        return HexFormat.of().parseHex(hex.replace(" ", ""));
    }

    static String upper(byte[] bytes) {
        return HexFormat.of().formatHex(bytes).toUpperCase(Locale.ROOT);
    }
}
