/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Long2LongHashMap;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * RFC 5080 §2.2.2 duplicate detection for Access-Requests, keyed like {@link ResponseCache} (source address, port,
 * Identifier, Request Authenticator). Unlike an Accounting-Response, an Access reply depends on the decision, so its
 * bytes are kept: a fixed ring of entries of up to {@link #MAX_REPLY} bytes, oldest replaced first, each valid for a
 * TTL. A request being decided is marked in flight, so its retransmissions are dropped instead of decided twice.
 * Owned by the auth agent thread; allocation-free after construction.
 */
final class ReplyCache {

    /** Replies above this size are not cached (the retransmission is decided again). */
    static final int MAX_REPLY = 1024;

    static final int MISSING = -1;
    static final int IN_FLIGHT = -2;

    private static final long IN_FLIGHT_VALUE = -1L;

    private final Long2LongHashMap index; // key → entry, or IN_FLIGHT_VALUE
    private final long[] keys;
    private final long[] expiries;
    private final int[] lengths;
    private final UnsafeBuffer bytes;
    private final int mask;
    private int next;
    private int size;

    ReplyCache(int entries) {
        int capacity = Integer.highestOneBit(Math.max(16, entries) - 1) << 1; // next power of two
        this.index = new Long2LongHashMap(capacity * 4, 0.5f, Long.MIN_VALUE);
        this.keys = new long[capacity];
        this.expiries = new long[capacity];
        this.lengths = new int[capacity];
        this.bytes = new UnsafeBuffer(new byte[capacity * MAX_REPLY]);
        this.mask = capacity - 1;
    }

    /** {@link #MISSING}, {@link #IN_FLIGHT}, or the entry holding a reply still valid at {@code now}. */
    int lookup(long key, long now) {
        long value = index.get(key);
        if (value == Long.MIN_VALUE) {
            return MISSING;
        }
        if (value == IN_FLIGHT_VALUE) {
            return IN_FLIGHT;
        }
        int entry = (int) value;
        if (expiries[entry] - now <= 0) {
            index.remove(key);
            lengths[entry] = 0;
            size--;
            return MISSING;
        }
        return entry;
    }

    void markInFlight(long key) {
        index.put(key, IN_FLIGHT_VALUE);
    }

    /** The request was not answered (dropped): its retransmission is decided anew. */
    void clearInFlight(long key) {
        if (index.get(key) == IN_FLIGHT_VALUE) {
            index.remove(key);
        }
    }

    /** Stores the reply for {@code key} (replacing its in-flight mark); too large replies only clear the mark. */
    void put(long key, DirectBuffer reply, int offset, int length, long expiry) {
        if (length > MAX_REPLY) {
            clearInFlight(key);
            return;
        }
        int entry = next;
        next = (next + 1) & mask;
        if (lengths[entry] > 0) { // replace the oldest
            if (index.get(keys[entry]) == entry) {
                index.remove(keys[entry]);
            }
            size--;
        }
        keys[entry] = key;
        expiries[entry] = expiry;
        lengths[entry] = length;
        bytes.putBytes(entry * MAX_REPLY, reply, offset, length);
        index.put(key, entry);
        size++;
    }

    /** Copies the cached reply of {@code entry} into {@code out}; returns its length. */
    int copy(int entry, MutableDirectBuffer out, int offset) {
        out.putBytes(offset, bytes, entry * MAX_REPLY, lengths[entry]);
        return lengths[entry];
    }

    int size() {
        return size;
    }
}
