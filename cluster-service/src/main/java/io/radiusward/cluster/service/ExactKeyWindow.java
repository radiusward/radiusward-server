/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import org.agrona.collections.Long2LongHashMap;

/**
 * Remembers exact event keys for a time window, for events that carry no monotonic progress
 * (Accounting-On/Off and other status types). Keys expire in insertion order; cluster time only.
 * Deterministic and allocation-free except when growing.
 */
public final class ExactKeyWindow {

    private final Long2LongHashMap expiries = new Long2LongHashMap(Long.MIN_VALUE);
    private long[] ringKeys = new long[256];
    private long[] ringExpiry = new long[256];
    private int head;
    private int count;

    /** Whether the key is present and not expired at {@code now}. */
    public boolean contains(long key, long now) {
        long expiry = expiries.get(key);
        return expiry != Long.MIN_VALUE && expiry > now;
    }

    /** Adds or refreshes a key. */
    public void add(long key, long expiry) {
        expiries.put(key, expiry);
        if (count == ringKeys.length) {
            grow();
        }
        int tail = (head + count) & (ringKeys.length - 1);
        ringKeys[tail] = key;
        ringExpiry[tail] = expiry;
        count++;
    }

    /** Drops expired keys; returns how many were removed. */
    public int evict(long now) {
        int removed = 0;
        while (count > 0 && ringExpiry[head] <= now) {
            long key = ringKeys[head];
            if (expiries.get(key) == ringExpiry[head]) { // not refreshed later
                expiries.remove(key);
                removed++;
            }
            head = (head + 1) & (ringKeys.length - 1);
            count--;
        }
        return removed;
    }

    public int size() {
        return expiries.size();
    }

    /** Visits live entries in insertion order (for snapshots). */
    public void forEach(EntryConsumer consumer) {
        for (int i = 0; i < count; i++) {
            int at = (head + i) & (ringKeys.length - 1);
            long key = ringKeys[at];
            if (expiries.get(key) == ringExpiry[at]) {
                consumer.accept(key, ringExpiry[at]);
            }
        }
    }

    /** Callback for {@link #forEach}. */
    @FunctionalInterface
    public interface EntryConsumer {
        void accept(long key, long expiry);
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
