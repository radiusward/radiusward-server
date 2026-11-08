/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import org.agrona.collections.Long2LongHashMap;

/**
 * RFC 5080 §2.2.2 duplicate detection at the gateway, keyed by source address, port, Identifier and Request
 * Authenticator. Stores only a state per request (~32 bytes): the Accounting-Response is deterministic, so a
 * COMMITTED retransmit is answered by re-encoding it from the incoming packet (ADR 0011). Entries expire in
 * insertion order. Owned by the UDP agent thread; allocation-free except when growing.
 */
final class ResponseCache {

    static final long MISSING = 0;
    static final long PENDING = 1;
    static final long COMMITTED = 2;

    /** Value of a PENDING entry: the correlation id of the submission in flight, tagged as PENDING. */
    static long pending(long correlationId) {
        return (correlationId << 2) | PENDING;
    }

    static long state(long value) {
        return value & 3;
    }

    static long correlationId(long value) {
        return value >>> 2;
    }

    private final Long2LongHashMap states = new Long2LongHashMap(MISSING);
    private final Long2LongHashMap expiries = new Long2LongHashMap(Long.MIN_VALUE);
    private long[] ringKeys = new long[1024];
    private long[] ringExpiry = new long[1024];
    private int head;
    private int count;

    long get(long key) {
        return states.get(key);
    }

    void put(long key, long state, long expiryNanos) {
        states.put(key, state);
        expiries.put(key, expiryNanos);
        if (count == ringKeys.length) {
            grow();
        }
        int tail = (head + count) & (ringKeys.length - 1);
        ringKeys[tail] = key;
        ringExpiry[tail] = expiryNanos;
        count++;
    }

    void remove(long key) {
        states.remove(key);
        expiries.remove(key);
    }

    /** Drops entries whose expiry passed; a key put again later lives on through its newer ring entry. */
    void evict(long nowNanos) {
        while (count > 0 && ringExpiry[head] - nowNanos <= 0) {
            long key = ringKeys[head];
            if (expiries.get(key) == ringExpiry[head]) {
                states.remove(key);
                expiries.remove(key);
            }
            head = (head + 1) & (ringKeys.length - 1);
            count--;
        }
    }

    int size() {
        return states.size();
    }

    static long key(int address, int port, int identifier, long authenticatorHi, long authenticatorLo) {
        long h = ((long) address << 32) | ((long) port << 8) | identifier;
        h ^= authenticatorHi * 0x9E37_79B9_7F4A_7C15L;
        h ^= Long.rotateLeft(authenticatorLo, 29) * 0xC2B2_AE3D_27D4_EB4FL;
        h ^= h >>> 31;
        return h == MISSING ? 1 : h;
    }

    private void grow() {
        long[] keys = new long[ringKeys.length * 2];
        long[] expiry = new long[ringKeys.length * 2];
        for (int i = 0; i < count; i++) {
            int at = (head + i) & (ringKeys.length - 1);
            keys[i] = ringKeys[at];
            expiry[i] = ringExpiry[at];
        }
        ringKeys = keys;
        ringExpiry = expiry;
        head = 0;
    }
}
