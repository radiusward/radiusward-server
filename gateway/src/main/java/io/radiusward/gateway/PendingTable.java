/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.net.InetSocketAddress;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Requests submitted to the cluster and not yet answered, in preallocated slots. A slot keeps exactly what
 * building the response needs: sender, NAS, Identifier, Request Authenticator, Proxy-State attributes and
 * whether to add a Message-Authenticator. The correlation id encodes slot and generation, so late or
 * duplicated commits for a reused slot are recognised. Owned by the UDP agent thread.
 */
final class PendingTable {

    /** Room for Proxy-State attributes per request; requests with more are dropped. */
    static final int PROXY_STATE_CAPACITY = 256;

    private final int capacity;
    private final int[] generation;
    private final boolean[] inUse;
    private final long[] cacheKey;
    private final long[] createdAt;
    private final long[] readyAt;
    private final int[] identifier;
    private final boolean[] withMessageAuthenticator;
    private final InetSocketAddress[] sender;
    private final NasClient[] nas;
    private final int[] proxyStateLength;
    private final UnsafeBuffer authenticators;
    private final UnsafeBuffer proxyStates;
    private final int[] free;
    private int freeCount;
    private int size;

    PendingTable(int capacity) {
        this.capacity = capacity;
        generation = new int[capacity];
        inUse = new boolean[capacity];
        cacheKey = new long[capacity];
        createdAt = new long[capacity];
        readyAt = new long[capacity];
        identifier = new int[capacity];
        withMessageAuthenticator = new boolean[capacity];
        sender = new InetSocketAddress[capacity];
        nas = new NasClient[capacity];
        proxyStateLength = new int[capacity];
        authenticators = new UnsafeBuffer(new byte[capacity * 16]);
        proxyStates = new UnsafeBuffer(new byte[capacity * PROXY_STATE_CAPACITY]);
        free = new int[capacity];
        for (int i = 0; i < capacity; i++) {
            free[i] = capacity - 1 - i;
        }
        freeCount = capacity;
    }

    /** Allocates a slot; returns its correlation id, or {@code -1} when full. */
    long allocate(long key, long now, InetSocketAddress from, NasClient client, int id, boolean withMa) {
        if (freeCount == 0) {
            return -1;
        }
        int slot = free[--freeCount];
        inUse[slot] = true;
        cacheKey[slot] = key;
        createdAt[slot] = now;
        readyAt[slot] = 0;
        sender[slot] = from;
        nas[slot] = client;
        identifier[slot] = id;
        withMessageAuthenticator[slot] = withMa;
        proxyStateLength[slot] = 0;
        size++;
        return ((long) generation[slot] << 32) | slot;
    }

    /** Slot of a correlation id, or {@code -1} if it was released or reused since. */
    int slotOf(long correlationId) {
        int slot = (int) correlationId;
        if (slot < 0 || slot >= capacity || !inUse[slot] || generation[slot] != (int) (correlationId >>> 32)) {
            return -1;
        }
        return slot;
    }

    /** Correlation id of a slot in use. */
    long correlationId(int slot) {
        return ((long) generation[slot] << 32) | slot;
    }

    void release(int slot) {
        inUse[slot] = false;
        sender[slot] = null;
        nas[slot] = null;
        generation[slot] = (generation[slot] + 1) & 0x3FFF_FFFF; // fits ResponseCache.pending()
        free[freeCount++] = slot;
        size--;
    }

    void authenticator(int slot, DirectBuffer source, int offset) {
        authenticators.putBytes(slot * 16, source, offset, 16);
    }

    /** Appends one Proxy-State attribute (header included); false if it does not fit. */
    boolean addProxyState(int slot, DirectBuffer source, int attributeOffset, int attributeLength) {
        int used = proxyStateLength[slot];
        if (used + attributeLength > PROXY_STATE_CAPACITY) {
            return false;
        }
        proxyStates.putBytes(slot * PROXY_STATE_CAPACITY + used, source, attributeOffset, attributeLength);
        proxyStateLength[slot] = used + attributeLength;
        return true;
    }

    boolean inUse(int slot) {
        return inUse[slot];
    }

    long cacheKey(int slot) {
        return cacheKey[slot];
    }

    long createdAt(int slot) {
        return createdAt[slot];
    }

    long readyAt(int slot) {
        return readyAt[slot];
    }

    void readyAt(int slot, long nanos) {
        readyAt[slot] = nanos;
    }

    int identifier(int slot) {
        return identifier[slot];
    }

    boolean withMessageAuthenticator(int slot) {
        return withMessageAuthenticator[slot];
    }

    InetSocketAddress sender(int slot) {
        return sender[slot];
    }

    NasClient nas(int slot) {
        return nas[slot];
    }

    UnsafeBuffer authenticators() {
        return authenticators;
    }

    UnsafeBuffer proxyStates() {
        return proxyStates;
    }

    int proxyStateOffset(int slot) {
        return slot * PROXY_STATE_CAPACITY;
    }

    int proxyStateLength(int slot) {
        return proxyStateLength[slot];
    }

    int capacity() {
        return capacity;
    }

    int size() {
        return size;
    }
}
