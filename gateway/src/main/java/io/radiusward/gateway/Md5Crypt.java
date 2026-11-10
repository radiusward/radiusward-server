/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5-crypt ({@code $1$salt$hash}, ADR 0048), the old default of Linux and the BSDs: 1000 rounds of MD5. Verification
 * only; weak by today's standards, accepted so that old password databases can be migrated.
 */
final class Md5Crypt {

    private static final String ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final byte[] MAGIC = "$1$".getBytes(StandardCharsets.US_ASCII);

    private Md5Crypt() {}

    static boolean supports(String stored) {
        return stored.startsWith("$1$");
    }

    static boolean verify(byte[] password, String stored) {
        String computed = crypt(password, stored);
        return computed != null
                && MessageDigest.isEqual(
                        computed.getBytes(StandardCharsets.US_ASCII), stored.getBytes(StandardCharsets.US_ASCII));
    }

    /** {@code $1$salt$hash} for the password and the salt of {@code setting}; {@code null} if it is not MD5-crypt. */
    static String crypt(byte[] password, String setting) {
        if (!supports(setting)) {
            return null;
        }
        int end = setting.indexOf('$', 3);
        String saltText = setting.substring(3, end < 0 ? setting.length() : end);
        if (saltText.length() > 8) {
            saltText = saltText.substring(0, 8);
        }
        byte[] salt = saltText.getBytes(StandardCharsets.US_ASCII);
        MessageDigest ctx = md5();
        ctx.update(password);
        ctx.update(MAGIC);
        ctx.update(salt);
        MessageDigest alt = md5();
        alt.update(password);
        alt.update(salt);
        alt.update(password);
        byte[] f = alt.digest();
        for (int left = password.length; left > 0; left -= 16) {
            ctx.update(f, 0, Math.min(16, left));
        }
        for (int i = password.length; i != 0; i >>>= 1) {
            ctx.update((i & 1) != 0 ? 0 : password.length == 0 ? 0 : password[0]);
        }
        f = ctx.digest();
        for (int i = 0; i < 1000; i++) {
            MessageDigest round = md5();
            round.update((i & 1) != 0 ? password : f);
            if (i % 3 != 0) {
                round.update(salt);
            }
            if (i % 7 != 0) {
                round.update(password);
            }
            round.update((i & 1) != 0 ? f : password);
            f = round.digest();
        }
        StringBuilder out = new StringBuilder("$1$").append(saltText).append('$');
        to64(out, (f[0] & 0xFF) << 16 | (f[6] & 0xFF) << 8 | (f[12] & 0xFF), 4);
        to64(out, (f[1] & 0xFF) << 16 | (f[7] & 0xFF) << 8 | (f[13] & 0xFF), 4);
        to64(out, (f[2] & 0xFF) << 16 | (f[8] & 0xFF) << 8 | (f[14] & 0xFF), 4);
        to64(out, (f[3] & 0xFF) << 16 | (f[9] & 0xFF) << 8 | (f[15] & 0xFF), 4);
        to64(out, (f[4] & 0xFF) << 16 | (f[10] & 0xFF) << 8 | (f[5] & 0xFF), 4);
        to64(out, f[11] & 0xFF, 2);
        return out.toString();
    }

    private static void to64(StringBuilder out, int v, int n) {
        while (n-- > 0) {
            out.append(ITOA64.charAt(v & 0x3f));
            v >>>= 6;
        }
    }

    private static MessageDigest md5() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
