/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * yescrypt (ADR 0048), the default password hash of current Linux distributions: {@code $y$} hashes as libxcrypt
 * writes them (no ROM, the standard pwxform flavour), and classic scrypt. Verification only. A port of the reference
 * implementation; memory use is 128·r·N bytes per check (16 MiB for the common {@code $y$j9T$}), so successful checks
 * are cached like other slow hashes.
 */
final class Yescrypt {

    static final int RW = 0x002;
    private static final int WORM = 1;
    private static final int ROUNDS_6 = 0x004;
    private static final int GATHER_4 = 0x010;
    private static final int SIMPLE_2 = 0x020;
    private static final int SBOX_12K = 0x080;
    private static final int RW_FLAVOR_MASK = 0x3fc;
    private static final int PREHASH = 0x10000000;

    private static final int PWX_SIMPLE = 2;
    private static final int PWX_GATHER = 4;
    private static final int PWX_ROUNDS = 6;
    private static final int S_WIDTH = 8;
    private static final int PWX_BYTES = PWX_GATHER * PWX_SIMPLE * 8;
    private static final int PWX_WORDS = PWX_BYTES / 4;
    private static final int S_BYTES = 3 * (1 << S_WIDTH) * PWX_SIMPLE * 8;
    private static final int S_WORDS = S_BYTES / 4;
    private static final int S_MASK = ((1 << S_WIDTH) - 1) * PWX_SIMPLE * 8;
    private static final int R_MIN = (PWX_BYTES + 127) / 128;
    private static final long MAX_MEMORY = 1L << 30; // refuse settings needing more than 1 GiB

    private static final String ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    private Yescrypt() {}

    static boolean supports(String stored) {
        return stored.startsWith("$y$");
    }

    /** Whether {@code password} matches a {@code $y$} hash; {@code false} for a malformed or unsupported one. */
    static boolean verify(byte[] password, String stored) {
        String computed = crypt(password, stored);
        return computed != null
                && MessageDigest.isEqual(
                        computed.getBytes(StandardCharsets.US_ASCII), stored.getBytes(StandardCharsets.US_ASCII));
    }

    /** The {@code $y$} hash of a password under the setting (or a whole hash); {@code null} if unusable. */
    static String crypt(byte[] password, String setting) {
        if (!setting.startsWith("$y$")) {
            return null;
        }
        int[] at = {3};
        long flavor = decodeUint32(setting, at, 0);
        if (flavor < 0) {
            return null;
        }
        int flags;
        if (flavor < RW) {
            flags = (int) flavor;
        } else if (flavor <= RW + (RW_FLAVOR_MASK >> 2)) {
            flags = RW + (int) ((flavor - RW) << 2);
        } else {
            return null;
        }
        long nLog2 = decodeUint32(setting, at, 1);
        if (nLog2 < 1 || nLog2 > 63) {
            return null;
        }
        long r = decodeUint32(setting, at, 1);
        if (r < 1) {
            return null;
        }
        long p = 1;
        long t = 0;
        if (at[0] < setting.length() && setting.charAt(at[0]) != '$') {
            long have = decodeUint32(setting, at, 1);
            if (have < 0 || (have & ~3) != 0) {
                return null; // g (hash upgrades) and ROMs are not supported
            }
            if ((have & 1) != 0) {
                p = decodeUint32(setting, at, 2);
            }
            if ((have & 2) != 0) {
                t = decodeUint32(setting, at, 1);
            }
            if (p < 1 || t < 0) {
                return null;
            }
        }
        if (at[0] >= setting.length() || setting.charAt(at[0]) != '$') {
            return null;
        }
        int prefixEnd = at[0] + 1;
        int saltEnd = setting.indexOf('$', prefixEnd);
        if (saltEnd < 0) {
            saltEnd = setting.length();
        }
        byte[] salt = decode64(setting.substring(prefixEnd, saltEnd));
        if (salt == null) {
            return null;
        }
        long n = 1L << nLog2;
        if (128L * r * n > MAX_MEMORY || r * p >= (1 << 30)) {
            return null;
        }
        byte[] hash = kdf(password, salt, flags, n, (int) r, (int) p, (int) t, 32);
        if (hash == null) {
            return null;
        }
        return setting.substring(0, saltEnd) + "$" + encode64(hash);
    }

    /** yescrypt_kdf: the pre-hash for large settings, then the body. */
    static byte[] kdf(byte[] password, byte[] salt, int flags, long n, int r, int p, int t, int length) {
        if ((flags & RW) != 0 && p >= 1 && n / p >= 0x100 && n / p * r >= 0x20000) {
            byte[] dk = body(password, salt, flags | PREHASH, n >> 6, r, p, 0, 32);
            if (dk == null) {
                return null;
            }
            password = dk;
        }
        return body(password, salt, flags, n, r, p, t, length);
    }

    /** yescrypt_kdf_body; classic scrypt with flags 0. */
    private static byte[] body(byte[] password, byte[] salt, int flags, long n, int r, int p, int t, int length) {
        int mode = flags & 3;
        if (mode == 0 && ((flags & ~PREHASH) != 0 || t != 0)) {
            return null;
        }
        if (mode == WORM && flags != WORM) {
            return null;
        }
        if (mode == RW && (flags & RW_FLAVOR_MASK) != (ROUNDS_6 | GATHER_4 | SIMPLE_2 | SBOX_12K)) {
            return null;
        }
        if (mode == 3 || (n & (n - 1)) != 0 || n <= 1 || r < 1 || p < 1) {
            return null;
        }
        if ((flags & RW) != 0 && (n / p <= 1 || r < R_MIN)) {
            return null;
        }
        if (128L * r * n > MAX_MEMORY) {
            return null;
        }
        byte[] passwd = password;
        if (flags != 0) {
            byte[] key = ((flags & PREHASH) != 0 ? "yescrypt-prehash" : "yescrypt").getBytes(StandardCharsets.US_ASCII);
            passwd = hmac(key, passwd);
        }
        int s = 32 * r;
        byte[] bBytes = pbkdf2(passwd, salt, 128 * r * p);
        int[] b = new int[s * p];
        for (int i = 0; i < b.length; i++) {
            b[i] = le32(bBytes, i * 4);
        }
        if (flags != 0) {
            passwd = java.util.Arrays.copyOf(bBytes, 32); // the reference copies B's start over its password buffer
        }
        int[] v = new int[(int) (s * n)];
        int[] xy = new int[2 * s];
        if ((flags & RW) != 0) {
            Pwx[] ctx = new Pwx[p];
            for (int i = 0; i < p; i++) {
                ctx[i] = new Pwx(new int[S_WORDS]);
            }
            passwd = smix(b, r, n, p, t, flags, v, xy, ctx, passwd);
        } else {
            for (int i = 0; i < p; i++) {
                int[] bi = java.util.Arrays.copyOfRange(b, i * s, (i + 1) * s);
                smix(bi, r, n, 1, t, flags, v, xy, null, null);
                System.arraycopy(bi, 0, b, i * s, s);
            }
        }
        byte[] finalB = new byte[b.length * 4];
        for (int i = 0; i < b.length; i++) {
            le32(finalB, i * 4, b[i]);
        }
        byte[] out = pbkdf2(passwd, finalB, Math.max(length, 32));
        if (flags != 0 && (flags & PREHASH) == 0) {
            byte[] clientKey = hmac(java.util.Arrays.copyOf(out, 32), "Client Key".getBytes(StandardCharsets.US_ASCII));
            byte[] storedKey = sha256(clientKey);
            System.arraycopy(storedKey, 0, out, 0, Math.min(length, 32));
        }
        return java.util.Arrays.copyOf(out, length);
    }

    /** The pwxform context: S-boxes S0, S1, S2 as word offsets into S, and the write index w. */
    private static final class Pwx {
        final int[] s;
        int s0;
        int s1;
        int s2;
        int w;

        Pwx(int[] s) {
            this.s = s;
        }
    }

    /** smix; returns the (possibly updated) password buffer of the RW mode. */
    private static byte[] smix(
            int[] b, int r, long n, int p, int t, int flags, int[] v, int[] xy, Pwx[] ctx, byte[] passwd) {
        int s = 32 * r;
        long nChunk = n / p;
        long nLoopAll = nChunk;
        if ((flags & RW) != 0) {
            if (t <= 1) {
                if (t != 0) {
                    nLoopAll *= 2;
                }
                nLoopAll = (nLoopAll + 2) / 3;
            } else {
                nLoopAll *= t - 1;
            }
        } else if (t != 0) {
            if (t == 1) {
                nLoopAll += (nLoopAll + 1) / 2;
            }
            nLoopAll *= t;
        }
        long nLoopRw = (flags & RW) != 0 ? nLoopAll / p : 0;
        nChunk &= ~1L;
        nLoopAll = (nLoopAll + 1) & ~1L;
        nLoopRw = (nLoopRw + 1) & ~1L;
        long vChunk = 0;
        for (int i = 0; i < p; i++, vChunk += nChunk) {
            long np = i < p - 1 ? nChunk : n - vChunk;
            int bOff = i * s;
            int vOff = (int) (vChunk * s);
            Pwx c = null;
            if ((flags & RW) != 0) {
                c = ctx[i];
                smix1(b, bOff, 1, S_BYTES / 128, 0, c.s, 0, xy, null);
                c.s2 = 0;
                c.s1 = c.s2 + (1 << S_WIDTH) * PWX_SIMPLE * 2;
                c.s0 = c.s1 + (1 << S_WIDTH) * PWX_SIMPLE * 2;
                c.w = 0;
                if (i == 0) {
                    byte[] key = new byte[64];
                    for (int k = 0; k < 16; k++) {
                        le32(key, k * 4, b[bOff + s - 16 + k]);
                    }
                    passwd = hmac(key, java.util.Arrays.copyOf(passwd, 32));
                }
            }
            smix1(b, bOff, r, np, flags, v, vOff, xy, c);
            smix2(b, bOff, r, p2floor(np), nLoopRw, flags, v, vOff, xy, c);
        }
        for (int i = 0; i < p; i++) {
            smix2(b, i * s, r, n, nLoopAll - nLoopRw, flags & ~RW, v, 0, xy, (flags & RW) != 0 ? ctx[i] : null);
        }
        return passwd;
    }

    private static void smix1(int[] b, int bOff, int r, long n, int flags, int[] v, int vOff, int[] xy, Pwx ctx) {
        int s = 32 * r;
        int[] x = xy;
        for (int k = 0; k < 2 * r; k++) {
            for (int i = 0; i < 16; i++) {
                x[k * 16 + i] = b[bOff + k * 16 + (i * 5 % 16)];
            }
        }
        for (long i = 0; i < n; i++) {
            System.arraycopy(x, 0, v, (int) (vOff + i * s), s);
            if ((flags & RW) != 0 && i > 1) {
                long j = wrap(integerify(x, r), i);
                xor(x, 0, v, (int) (vOff + j * s), s);
            }
            if (ctx != null) {
                blockmixPwxform(x, ctx, r);
            } else {
                blockmixSalsa8(x, xy, s, r);
            }
        }
        for (int k = 0; k < 2 * r; k++) {
            for (int i = 0; i < 16; i++) {
                b[bOff + k * 16 + (i * 5 % 16)] = x[k * 16 + i];
            }
        }
    }

    private static void smix2(
            int[] b, int bOff, int r, long n, long nLoop, int flags, int[] v, int vOff, int[] xy, Pwx ctx) {
        int s = 32 * r;
        int[] x = xy;
        for (int k = 0; k < 2 * r; k++) {
            for (int i = 0; i < 16; i++) {
                x[k * 16 + i] = b[bOff + k * 16 + (i * 5 % 16)];
            }
        }
        for (long i = 0; i < nLoop; i++) {
            long j = integerify(x, r) & (n - 1);
            xor(x, 0, v, (int) (vOff + j * s), s);
            if ((flags & RW) != 0) {
                System.arraycopy(x, 0, v, (int) (vOff + j * s), s);
            }
            if (ctx != null) {
                blockmixPwxform(x, ctx, r);
            } else {
                blockmixSalsa8(x, xy, s, r);
            }
        }
        for (int k = 0; k < 2 * r; k++) {
            for (int i = 0; i < 16; i++) {
                b[bOff + k * 16 + (i * 5 % 16)] = x[k * 16 + i];
            }
        }
    }

    /** BlockMix with Salsa20/8 over X (at 0 of xy); Y is the second half of xy, at {@code yOff}. */
    private static void blockmixSalsa8(int[] xy, int[] same, int yOff, int r) {
        int[] t = new int[16];
        System.arraycopy(xy, (2 * r - 1) * 16, t, 0, 16);
        for (int i = 0; i < 2 * r; i++) {
            xor(t, 0, xy, i * 16, 16);
            salsa20(t, 0, 8);
            System.arraycopy(t, 0, xy, yOff + i * 16, 16);
        }
        for (int i = 0; i < r; i++) {
            System.arraycopy(xy, yOff + (i * 2) * 16, xy, i * 16, 16);
        }
        for (int i = 0; i < r; i++) {
            System.arraycopy(xy, yOff + (i * 2 + 1) * 16, xy, (i + r) * 16, 16);
        }
    }

    private static void blockmixPwxform(int[] b, Pwx ctx, int r) {
        int[] x = new int[PWX_WORDS];
        int r1 = 128 * r / PWX_BYTES;
        System.arraycopy(b, (r1 - 1) * PWX_WORDS, x, 0, PWX_WORDS);
        for (int i = 0; i < r1; i++) {
            if (r1 > 1) {
                xor(x, 0, b, i * PWX_WORDS, PWX_WORDS);
            }
            pwxform(x, ctx);
            System.arraycopy(x, 0, b, i * PWX_WORDS, PWX_WORDS);
        }
        int i = (r1 - 1) * PWX_BYTES / 64;
        salsa20(b, i * 16, 2);
        for (i++; i < 2 * r; i++) {
            xor(b, i * 16, b, (i - 1) * 16, 16);
            salsa20(b, i * 16, 2);
        }
    }

    private static void pwxform(int[] x, Pwx ctx) {
        int[] s = ctx.s;
        int s0 = ctx.s0;
        int s1 = ctx.s1;
        int s2 = ctx.s2;
        int w = ctx.w;
        for (int i = 0; i < PWX_ROUNDS; i++) {
            for (int j = 0; j < PWX_GATHER; j++) {
                int xl = x[(j * PWX_SIMPLE) * 2];
                int xh = x[(j * PWX_SIMPLE) * 2 + 1];
                int p0 = s0 + ((xl & S_MASK) >>> 3) * 2;
                int p1 = s1 + ((xh & S_MASK) >>> 3) * 2;
                for (int k = 0; k < PWX_SIMPLE; k++) {
                    long sv0 = ((long) s[p0 + k * 2 + 1] << 32) + (s[p0 + k * 2] & 0xFFFFFFFFL);
                    long sv1 = ((long) s[p1 + k * 2 + 1] << 32) + (s[p1 + k * 2] & 0xFFFFFFFFL);
                    int at = (j * PWX_SIMPLE + k) * 2;
                    long v = (x[at + 1] & 0xFFFFFFFFL) * (x[at] & 0xFFFFFFFFL);
                    v += sv0;
                    v ^= sv1;
                    x[at] = (int) v;
                    x[at + 1] = (int) (v >>> 32);
                    if (i != 0 && i != PWX_ROUNDS - 1) {
                        s[s2 + w * 2] = (int) v;
                        s[s2 + w * 2 + 1] = (int) (v >>> 32);
                        w++;
                    }
                }
            }
        }
        ctx.s0 = s2;
        ctx.s1 = s0;
        ctx.s2 = s1;
        ctx.w = w & ((1 << S_WIDTH) * PWX_SIMPLE - 1);
    }

    /** The Salsa20 core over 16 words at {@code off}, on the shuffled layout the reference keeps. */
    private static void salsa20(int[] b, int off, int rounds) {
        int[] x = new int[16];
        for (int i = 0; i < 16; i++) {
            x[i * 5 % 16] = b[off + i];
        }
        for (int i = 0; i < rounds; i += 2) {
            x[4] ^= Integer.rotateLeft(x[0] + x[12], 7);
            x[8] ^= Integer.rotateLeft(x[4] + x[0], 9);
            x[12] ^= Integer.rotateLeft(x[8] + x[4], 13);
            x[0] ^= Integer.rotateLeft(x[12] + x[8], 18);
            x[9] ^= Integer.rotateLeft(x[5] + x[1], 7);
            x[13] ^= Integer.rotateLeft(x[9] + x[5], 9);
            x[1] ^= Integer.rotateLeft(x[13] + x[9], 13);
            x[5] ^= Integer.rotateLeft(x[1] + x[13], 18);
            x[14] ^= Integer.rotateLeft(x[10] + x[6], 7);
            x[2] ^= Integer.rotateLeft(x[14] + x[10], 9);
            x[6] ^= Integer.rotateLeft(x[2] + x[14], 13);
            x[10] ^= Integer.rotateLeft(x[6] + x[2], 18);
            x[3] ^= Integer.rotateLeft(x[15] + x[11], 7);
            x[7] ^= Integer.rotateLeft(x[3] + x[15], 9);
            x[11] ^= Integer.rotateLeft(x[7] + x[3], 13);
            x[15] ^= Integer.rotateLeft(x[11] + x[7], 18);
            x[1] ^= Integer.rotateLeft(x[0] + x[3], 7);
            x[2] ^= Integer.rotateLeft(x[1] + x[0], 9);
            x[3] ^= Integer.rotateLeft(x[2] + x[1], 13);
            x[0] ^= Integer.rotateLeft(x[3] + x[2], 18);
            x[6] ^= Integer.rotateLeft(x[5] + x[4], 7);
            x[7] ^= Integer.rotateLeft(x[6] + x[5], 9);
            x[4] ^= Integer.rotateLeft(x[7] + x[6], 13);
            x[5] ^= Integer.rotateLeft(x[4] + x[7], 18);
            x[11] ^= Integer.rotateLeft(x[10] + x[9], 7);
            x[8] ^= Integer.rotateLeft(x[11] + x[10], 9);
            x[9] ^= Integer.rotateLeft(x[8] + x[11], 13);
            x[10] ^= Integer.rotateLeft(x[9] + x[8], 18);
            x[12] ^= Integer.rotateLeft(x[15] + x[14], 7);
            x[13] ^= Integer.rotateLeft(x[12] + x[15], 9);
            x[14] ^= Integer.rotateLeft(x[13] + x[12], 13);
            x[15] ^= Integer.rotateLeft(x[14] + x[13], 18);
        }
        for (int i = 0; i < 16; i++) {
            b[off + i] += x[i * 5 % 16];
        }
    }

    private static long integerify(int[] x, int r) {
        int at = (2 * r - 1) * 16;
        return ((x[at + 13] & 0xFFFFFFFFL) << 32) + (x[at] & 0xFFFFFFFFL);
    }

    private static long p2floor(long x) {
        long y;
        while ((y = x & (x - 1)) != 0) {
            x = y;
        }
        return x;
    }

    private static long wrap(long x, long i) {
        long n = p2floor(i);
        return (x & (n - 1)) + (i - n);
    }

    private static void xor(int[] dst, int dstOff, int[] src, int srcOff, int count) {
        for (int i = 0; i < count; i++) {
            dst[dstOff + i] ^= src[srcOff + i];
        }
    }

    // ---- the $y$ encoding --------------------------------------------------------------------------------------

    private static int atoi64(char c) {
        int i = ITOA64.indexOf(c);
        return i < 0 ? 64 : i;
    }

    /** decode64_uint32: a variable-length number; {@code -1} if malformed. Advances {@code at[0]}. */
    static long decodeUint32(String s, int[] at, long min) {
        if (at[0] >= s.length()) {
            return -1;
        }
        long start = 0;
        long end = 47;
        int chars = 1;
        int bits = 0;
        int c = atoi64(s.charAt(at[0]++));
        if (c > 63) {
            return -1;
        }
        long dst = min;
        while (c > end) {
            dst += (end + 1 - start) << bits;
            start = end + 1;
            end = start + (62 - end) / 2;
            chars++;
            bits += 6;
        }
        dst += (c - start) << bits;
        while (--chars > 0) {
            if (at[0] >= s.length()) {
                return -1;
            }
            c = atoi64(s.charAt(at[0]++));
            if (c > 63) {
                return -1;
            }
            bits -= 6;
            dst += (long) c << bits;
        }
        return dst > 0xFFFFFFFFL ? -1 : dst;
    }

    /** decode64: little-endian groups of up to 24 bits; {@code null} if malformed. */
    static byte[] decode64(String src) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int i = 0;
        while (i < src.length()) {
            int value = 0;
            int bits = 0;
            while (i < src.length() && bits < 24) {
                int c = atoi64(src.charAt(i));
                if (c > 63) {
                    return null;
                }
                i++;
                value |= c << bits;
                bits += 6;
            }
            if (bits < 12) {
                return null;
            }
            while (bits >= 8) {
                out.write(value & 0xFF);
                value >>>= 8;
                bits -= 8;
            }
            if (value != 0) {
                return null;
            }
        }
        return out.size() > 64 ? null : out.toByteArray();
    }

    /** encode64: groups of up to three bytes, little-endian, six bits per character. */
    static String encode64(byte[] src) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < src.length; ) {
            int value = 0;
            int bits = 0;
            do {
                value |= (src[i++] & 0xFF) << bits;
                bits += 8;
            } while (bits < 24 && i < src.length);
            for (int b = 0; b < bits; b += 6) {
                out.append(ITOA64.charAt(value & 0x3f));
                value >>>= 6;
            }
        }
        return out.toString();
    }

    // ---- primitives --------------------------------------------------------------------------------------------

    private static int le32(byte[] b, int at) {
        return (b[at] & 0xFF) | (b[at + 1] & 0xFF) << 8 | (b[at + 2] & 0xFF) << 16 | (b[at + 3] & 0xFF) << 24;
    }

    private static void le32(byte[] b, int at, int v) {
        b[at] = (byte) v;
        b[at + 1] = (byte) (v >>> 8);
        b[at + 2] = (byte) (v >>> 16);
        b[at + 3] = (byte) (v >>> 24);
    }

    private static byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha256(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** PBKDF2-HMAC-SHA256 with one iteration. */
    static byte[] pbkdf2(byte[] password, byte[] salt, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(password.length == 0 ? new byte[1] : password, "HmacSHA256"));
            byte[] out = new byte[length];
            for (int block = 1, at = 0; at < length; block++) {
                mac.update(salt);
                mac.update(
                        new byte[] {(byte) (block >>> 24), (byte) (block >>> 16), (byte) (block >>> 8), (byte) block});
                byte[] u = mac.doFinal();
                int n = Math.min(u.length, length - at);
                System.arraycopy(u, 0, out, at, n);
                at += n;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
