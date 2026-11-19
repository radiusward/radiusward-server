/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * Packets recorded as hex: a vendor fixture's {@code packet:} line ({@code radclient decode --fixture} writes them), or
 * a file of hex digits with spaces, line breaks and {@code #} comments. {@link RadiusClient#replay} sends them again.
 */
public final class RecordedPacket {

    private RecordedPacket() {}

    /** The packet of a fixture or hex file. */
    public static byte[] read(Path file) throws IOException {
        String text = Files.readString(file, StandardCharsets.UTF_8);
        String hex = text;
        for (String line : text.split("\n")) {
            if (line.startsWith("packet:")) {
                hex = line.substring("packet:".length());
            }
        }
        try {
            return hex(hex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(file + ": no packet hex found", e);
        }
    }

    /** Hex digits as printed or pasted: spaces, line breaks and {@code #} comments in between are ignored. */
    public static byte[] hex(String text) {
        String digits = text.replaceAll("(?m)#.*$", "").replaceAll("\\s+", "");
        if (digits.startsWith("0x") || digits.startsWith("0X")) {
            digits = digits.substring(2);
        }
        return HexFormat.of().parseHex(digits);
    }
}
