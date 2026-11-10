/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Time-based one-time passwords (RFC 6238, HMAC-SHA-1 as authenticator apps use it) as a second factor for PAP
 * (ADR 0053). A user with {@code TOTP-Secret := <base32>} needs a code: in {@code challenge} mode an Access-Challenge
 * asks for it once the password is right; in {@code append} mode it follows the password in the same request.
 *
 * @param append the code is appended to the password instead of asked for
 * @param digits code length (6 or 8)
 * @param window steps accepted before and after the current one (clock drift)
 * @param timeout how long a challenge waits for the code
 */
record Totp(boolean append, int digits, int window, Duration step, Duration timeout, String prompt) {

    static final Totp DEFAULT = new Totp(
            false, 6, 1, Duration.ofSeconds(30), Duration.ofSeconds(60), "Enter the code from your authenticator app");

    static Totp from(Config config) {
        String mode = config.string("auth.totp.mode", "challenge").trim().toLowerCase(Locale.ROOT);
        if (!mode.equals("challenge") && !mode.equals("append")) {
            throw new ConfigException("auth.totp.mode: challenge or append");
        }
        int digits = config.integer("auth.totp.digits", 6);
        if (digits != 6 && digits != 8) {
            throw new ConfigException("auth.totp.digits: 6 or 8");
        }
        int window = config.integer("auth.totp.window", 1);
        if (window < 0 || window > 10) {
            throw new ConfigException("auth.totp.window: 0 to 10 steps");
        }
        return new Totp(
                mode.equals("append"),
                digits,
                window,
                Duration.ofSeconds(30),
                config.duration("auth.totp.timeout", Duration.ofSeconds(60)),
                config.string("auth.totp.prompt", DEFAULT.prompt()));
    }

    /**
     * The time step whose code {@code code} is, within the window around {@code epochSeconds}, or {@code -1}.
     * Compares every candidate in constant time.
     */
    long match(byte[] key, String code, long epochSeconds) {
        if (code.length() != digits || !code.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return -1;
        }
        long current = Math.floorDiv(epochSeconds, step.toSeconds());
        long found = -1;
        for (long s = current - window; s <= current + window; s++) {
            if (MessageDigest.isEqual(code(key, s, digits).getBytes(), code.getBytes()) && found < 0) {
                found = s;
            }
        }
        return found;
    }

    /** RFC 4226's HOTP value of a counter, zero-padded. */
    static String code(byte[] key, long counter, int digits) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] h = mac.doFinal(new byte[] {
                (byte) (counter >>> 56),
                (byte) (counter >>> 48),
                (byte) (counter >>> 40),
                (byte) (counter >>> 32),
                (byte) (counter >>> 24),
                (byte) (counter >>> 16),
                (byte) (counter >>> 8),
                (byte) counter
            });
            int offset = h[h.length - 1] & 0x0F;
            int binary = (h[offset] & 0x7F) << 24
                    | (h[offset + 1] & 0xFF) << 16
                    | (h[offset + 2] & 0xFF) << 8
                    | (h[offset + 3] & 0xFF);
            int modulo = digits == 8 ? 100_000_000 : 1_000_000;
            String value = Integer.toString(binary % modulo);
            return "0".repeat(digits - value.length()) + value;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** RFC 4648 base32 (case, spaces, dashes and padding ignored); {@code null} if malformed or shorter than 80 bits. */
    static byte[] base32(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        for (char c : text.toCharArray()) {
            int v;
            if (c >= 'A' && c <= 'Z') {
                v = c - 'A';
            } else if (c >= 'a' && c <= 'z') {
                v = c - 'a';
            } else if (c >= '2' && c <= '7') {
                v = c - '2' + 26;
            } else if (c == ' ' || c == '-' || c == '=') {
                continue;
            } else {
                return null;
            }
            buffer = buffer << 5 | v;
            bits += 5;
            if (bits >= 8) {
                out.write(buffer >>> (bits - 8) & 0xFF);
                bits -= 8;
            }
        }
        byte[] key = out.toByteArray();
        return key.length < 10 ? null : key;
    }
}
