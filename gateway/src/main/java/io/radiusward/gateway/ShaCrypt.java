/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-crypt, the {@code $5$} (SHA-256) and {@code $6$} (SHA-512) formats of crypt(3), as specified by Ulrich Drepper
 * ("Unix crypt using SHA-256 and SHA-512"), including {@code rounds=N} (1000 … 999,999,999, default 5000) and salts of
 * up to 16 characters. Verified against the specification's test vectors.
 */
final class ShaCrypt {

    private static final String ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int DEFAULT_ROUNDS = 5000;
    private static final int[][] ORDER_256 = {
        {0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14},
        {15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}
    };
    private static final int[][] ORDER_512 = {
        {0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48},
        {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13},
        {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}
    };

    private ShaCrypt() {}

    /** Whether {@code stored} is a {@code $5$} or {@code $6$} hash. */
    static boolean supports(String stored) {
        return stored.startsWith("$5$") || stored.startsWith("$6$");
    }

    /** Whether {@code password} produces {@code stored}; constant-time comparison. */
    static boolean verify(byte[] password, String stored) {
        String computed = crypt(password, stored);
        return computed != null
                && MessageDigest.isEqual(
                        computed.getBytes(StandardCharsets.US_ASCII), stored.getBytes(StandardCharsets.US_ASCII));
    }

    /** The hash of {@code password} with the parameters of {@code setting} ({@code $6$[rounds=N$]salt[$…]}). */
    static String crypt(byte[] password, String setting) {
        boolean sha512 = setting.startsWith("$6$");
        if (!sha512 && !setting.startsWith("$5$")) {
            return null;
        }
        String rest = setting.substring(3);
        int rounds = DEFAULT_ROUNDS;
        boolean customRounds = false;
        if (rest.startsWith("rounds=")) {
            int end = rest.indexOf('$');
            if (end < 0) {
                return null;
            }
            try {
                rounds = Math.max(1000, Math.min(999_999_999, Integer.parseInt(rest.substring(7, end))));
            } catch (NumberFormatException e) {
                return null;
            }
            customRounds = true;
            rest = rest.substring(end + 1);
        }
        int saltEnd = rest.indexOf('$');
        String saltText = saltEnd < 0 ? rest : rest.substring(0, saltEnd);
        byte[] salt = saltText.substring(0, Math.min(16, saltText.length())).getBytes(StandardCharsets.UTF_8);

        MessageDigest md = digest(sha512 ? "SHA-512" : "SHA-256");
        int size = md.getDigestLength();

        md.update(password);
        md.update(salt);
        md.update(password);
        byte[] b = md.digest();

        md.update(password);
        md.update(salt);
        for (int n = password.length; n > 0; n -= size) {
            md.update(b, 0, Math.min(n, size));
        }
        for (int n = password.length; n > 0; n >>= 1) {
            if ((n & 1) != 0) {
                md.update(b);
            } else {
                md.update(password);
            }
        }
        byte[] a = md.digest();

        for (int i = 0; i < password.length; i++) {
            md.update(password);
        }
        byte[] p = fill(md.digest(), password.length);

        for (int i = 0; i < 16 + (a[0] & 0xFF); i++) {
            md.update(salt);
        }
        byte[] s = fill(md.digest(), salt.length);

        byte[] c = a;
        for (int i = 0; i < rounds; i++) {
            if ((i & 1) != 0) {
                md.update(p);
            } else {
                md.update(c);
            }
            if (i % 3 != 0) {
                md.update(s);
            }
            if (i % 7 != 0) {
                md.update(p);
            }
            if ((i & 1) != 0) {
                md.update(c);
            } else {
                md.update(p);
            }
            c = md.digest();
        }

        StringBuilder out = new StringBuilder(sha512 ? "$6$" : "$5$");
        if (customRounds) {
            out.append("rounds=").append(rounds).append('$');
        }
        out.append(new String(salt, StandardCharsets.UTF_8)).append('$');
        for (int[] o : sha512 ? ORDER_512 : ORDER_256) {
            b64(out, c[o[0]], c[o[1]], c[o[2]], 4);
        }
        if (sha512) {
            b64(out, (byte) 0, (byte) 0, c[63], 2);
        } else {
            b64(out, (byte) 0, c[31], c[30], 3);
        }
        return out.toString();
    }

    private static byte[] fill(byte[] digest, int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = digest[i % digest.length];
        }
        return out;
    }

    private static void b64(StringBuilder out, byte b2, byte b1, byte b0, int n) {
        int w = ((b2 & 0xFF) << 16) | ((b1 & 0xFF) << 8) | (b0 & 0xFF);
        for (int i = 0; i < n; i++) {
            out.append(ITOA64.charAt(w & 0x3F));
            w >>>= 6;
        }
    }

    private static MessageDigest digest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " is required by the Java platform", e);
        }
    }
}
