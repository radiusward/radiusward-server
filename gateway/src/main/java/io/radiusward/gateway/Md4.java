/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

/**
 * MD4 (RFC 1320), which the JDK does not offer to applications. Used only where a protocol fixes it: the NT password
 * hash of MS-CHAP and its hash. Never for anything new.
 */
final class Md4 {

    private Md4() {}

    static byte[] digest(byte[] message) {
        long bitLength = (long) message.length * 8;
        int padded = ((message.length + 8) / 64 + 1) * 64;
        byte[] m = new byte[padded];
        System.arraycopy(message, 0, m, 0, message.length);
        m[message.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            m[padded - 8 + i] = (byte) (bitLength >>> (8 * i));
        }
        int a = 0x67452301;
        int b = 0xefcdab89;
        int c = 0x98badcfe;
        int d = 0x10325476;
        int[] x = new int[16];
        for (int block = 0; block < padded; block += 64) {
            for (int i = 0; i < 16; i++) {
                int o = block + i * 4;
                x[i] = (m[o] & 0xFF) | (m[o + 1] & 0xFF) << 8 | (m[o + 2] & 0xFF) << 16 | (m[o + 3] & 0xFF) << 24;
            }
            int aa = a;
            int bb = b;
            int cc = c;
            int dd = d;
            for (int i : new int[] {0, 4, 8, 12}) { // round 1: F, shifts 3 7 11 19
                a = Integer.rotateLeft(a + ((b & c) | (~b & d)) + x[i], 3);
                d = Integer.rotateLeft(d + ((a & b) | (~a & c)) + x[i + 1], 7);
                c = Integer.rotateLeft(c + ((d & a) | (~d & b)) + x[i + 2], 11);
                b = Integer.rotateLeft(b + ((c & d) | (~c & a)) + x[i + 3], 19);
            }
            for (int i : new int[] {0, 1, 2, 3}) { // round 2: G, shifts 3 5 9 13
                a = Integer.rotateLeft(a + ((b & c) | (b & d) | (c & d)) + x[i] + 0x5a827999, 3);
                d = Integer.rotateLeft(d + ((a & b) | (a & c) | (b & c)) + x[i + 4] + 0x5a827999, 5);
                c = Integer.rotateLeft(c + ((d & a) | (d & b) | (a & b)) + x[i + 8] + 0x5a827999, 9);
                b = Integer.rotateLeft(b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5a827999, 13);
            }
            for (int i : new int[] {0, 2, 1, 3}) { // round 3: H, shifts 3 9 11 15
                a = Integer.rotateLeft(a + (b ^ c ^ d) + x[i] + 0x6ed9eba1, 3);
                d = Integer.rotateLeft(d + (a ^ b ^ c) + x[i + 8] + 0x6ed9eba1, 9);
                c = Integer.rotateLeft(c + (d ^ a ^ b) + x[i + 4] + 0x6ed9eba1, 11);
                b = Integer.rotateLeft(b + (c ^ d ^ a) + x[i + 12] + 0x6ed9eba1, 15);
            }
            a += aa;
            b += bb;
            c += cc;
            d += dd;
        }
        byte[] out = new byte[16];
        int[] words = {a, b, c, d};
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) (words[i / 4] >>> (8 * (i % 4)));
        }
        return out;
    }
}
