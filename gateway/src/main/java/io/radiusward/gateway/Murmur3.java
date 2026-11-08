/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static java.nio.ByteOrder.LITTLE_ENDIAN;

import org.agrona.DirectBuffer;

/**
 * MurmurHash3 x64 128 (Austin Appleby, public domain) over a {@link DirectBuffer} region, allocation-free.
 * The event keys depend on it, so it is pinned and tested against reference vectors: changing it would make
 * the gateway compute different keys than the ones already in the cluster's dedup state.
 */
public final class Murmur3 {

    private static final long C1 = 0x87c3_7b91_1142_53d5L;
    private static final long C2 = 0x4cf5_ad43_2745_937fL;

    private long h1;
    private long h2;

    /** Hashes {@code buffer[offset, offset + length)} with seed 0; read the result with {@link #hi()}, {@link #lo()}. */
    public Murmur3 hash(DirectBuffer buffer, int offset, int length) {
        long a = 0;
        long b = 0;
        int blocks = length >>> 4;
        for (int i = 0; i < blocks; i++) {
            int at = offset + (i << 4);
            long k1 = buffer.getLong(at, LITTLE_ENDIAN);
            long k2 = buffer.getLong(at + 8, LITTLE_ENDIAN);
            k1 *= C1;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= C2;
            a ^= k1;
            a = Long.rotateLeft(a, 27);
            a += b;
            a = a * 5 + 0x52dce729;
            k2 *= C2;
            k2 = Long.rotateLeft(k2, 33);
            k2 *= C1;
            b ^= k2;
            b = Long.rotateLeft(b, 31);
            b += a;
            b = b * 5 + 0x38495ab5;
        }
        int tail = offset + (blocks << 4);
        int rem = length & 15;
        long k1 = 0;
        long k2 = 0;
        for (int i = rem - 1; i >= 8; i--) {
            k2 ^= (buffer.getByte(tail + i) & 0xFFL) << ((i - 8) * 8);
        }
        if (rem > 8) {
            k2 *= C2;
            k2 = Long.rotateLeft(k2, 33);
            k2 *= C1;
            b ^= k2;
        }
        for (int i = Math.min(rem, 8) - 1; i >= 0; i--) {
            k1 ^= (buffer.getByte(tail + i) & 0xFFL) << (i * 8);
        }
        if (rem > 0) {
            k1 *= C1;
            k1 = Long.rotateLeft(k1, 31);
            k1 *= C2;
            a ^= k1;
        }
        a ^= length;
        b ^= length;
        a += b;
        b += a;
        a = fmix(a);
        b = fmix(b);
        a += b;
        b += a;
        h1 = a;
        h2 = b;
        return this;
    }

    public long hi() {
        return h1;
    }

    public long lo() {
        return h2;
    }

    private static long fmix(long k) {
        k ^= k >>> 33;
        k *= 0xff51_afd7_ed55_8ccdL;
        k ^= k >>> 33;
        k *= 0xc4ce_b9fe_1a85_ec53L;
        k ^= k >>> 33;
        return k;
    }
}
