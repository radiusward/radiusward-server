/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import org.agrona.collections.Int2IntHashMap;

/**
 * Accounting sessions stored as columns of primitive arrays (ADR 0012): no object per session, ~75 bytes per
 * session plus a 4 byte open-addressing index slot, allocation only when a new chunk or a larger index is
 * needed.
 *
 * <p>Slots are allocated in chunks of {@value #CHUNK_SIZE}; freed slots are reused LIFO. A session is
 * identified by its 128 bit key. Every session is also linked into a per-NAS list so Accounting-On/Off can
 * close all sessions of a NAS.
 *
 * <p>Deterministic: the same sequence of calls produces the same slots and the same iteration order, which
 * the replicated state machine relies on. Not thread-safe.
 */
public final class SessionStore {

    public static final byte FREE = 0;
    public static final byte ACTIVE = 1;
    public static final byte STOPPED = 2;

    /** Presence bits in {@link #flags(int)}. */
    public static final byte HAS_SESSION_TIME = 1;

    public static final byte HAS_EVENT_TIMESTAMP = 2;

    static final int CHUNK_SHIFT = 14;
    static final int CHUNK_SIZE = 1 << CHUNK_SHIFT;
    private static final int CHUNK_MASK = CHUNK_SIZE - 1;
    private static final int MAX_CHUNKS = 1 << 14; // 268M slots
    private static final int NONE = -1;

    private final long[][] keyHi = new long[MAX_CHUNKS][];
    private final long[][] keyLo = new long[MAX_CHUNKS][];
    private final long[][] inputOctets = new long[MAX_CHUNKS][];
    private final long[][] outputOctets = new long[MAX_CHUNKS][];
    private final int[][] nasId = new int[MAX_CHUNKS][];
    private final int[][] sessionTime = new int[MAX_CHUNKS][];
    private final int[][] eventTimestamp = new int[MAX_CHUNKS][];
    private final int[][] startKey = new int[MAX_CHUNKS][];
    private final int[][] lastSeen = new int[MAX_CHUNKS][];
    private final int[][] tombstoneUntil = new int[MAX_CHUNKS][];
    private final int[][] prev = new int[MAX_CHUNKS][];
    private final int[][] next = new int[MAX_CHUNKS][];
    private final byte[][] state = new byte[MAX_CHUNKS][];
    private final byte[][] statusType = new byte[MAX_CHUNKS][];
    private final byte[][] flags = new byte[MAX_CHUNKS][];
    private final char[][] idleMinutes = new char[MAX_CHUNKS][];

    private int chunks;
    private int highWater; // slots ever handed out
    private int[] freeSlots = new int[64];
    private int freeCount;
    private int size;
    private int activeCount;

    private int[] index; // slot + 1, 0 = empty
    private int indexMask;

    private final Int2IntHashMap nasHead = new Int2IntHashMap(NONE);

    public SessionStore() {
        index = new int[1 << 10];
        indexMask = index.length - 1;
    }

    // ---- lookup and lifecycle --------------------------------------------------------------------

    /** Slot of the session, or {@code -1}. Allocation-free. */
    public int find(long hi, long lo) {
        int i = bucket(hi);
        while (true) {
            int entry = index[i];
            if (entry == 0) {
                return NONE;
            }
            int slot = entry - 1;
            if (keyHi[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] == hi
                    && keyLo[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] == lo) {
                return slot;
            }
            i = (i + 1) & indexMask;
        }
    }

    /** Inserts a new session (the key must not exist) in the given state and returns its slot. */
    public int insert(long hi, long lo, int nas, byte initialState) {
        if ((size + 1) * 10L > index.length * 7L) {
            growIndex();
        }
        int slot = allocateSlot();
        int c = slot >>> CHUNK_SHIFT;
        int o = slot & CHUNK_MASK;
        keyHi[c][o] = hi;
        keyLo[c][o] = lo;
        nasId[c][o] = nas;
        state[c][o] = initialState;
        statusType[c][o] = 0;
        flags[c][o] = 0;
        sessionTime[c][o] = 0;
        eventTimestamp[c][o] = 0;
        inputOctets[c][o] = 0;
        outputOctets[c][o] = 0;
        startKey[c][o] = 0;
        lastSeen[c][o] = 0;
        tombstoneUntil[c][o] = 0;
        idleMinutes[c][o] = 0;
        linkNas(slot, nas);

        int i = bucket(hi);
        while (index[i] != 0) {
            i = (i + 1) & indexMask;
        }
        index[i] = slot + 1;
        size++;
        if (initialState == ACTIVE) {
            activeCount++;
        }
        return slot;
    }

    /** Removes a session and frees its slot. */
    public void remove(int slot) {
        int c = slot >>> CHUNK_SHIFT;
        int o = slot & CHUNK_MASK;
        removeFromIndex(slot, keyHi[c][o]);
        unlinkNas(slot);
        if (state[c][o] == ACTIVE) {
            activeCount--;
        }
        state[c][o] = FREE;
        if (freeCount == freeSlots.length) {
            int[] grown = new int[freeSlots.length * 2];
            System.arraycopy(freeSlots, 0, grown, 0, freeCount);
            freeSlots = grown;
        }
        freeSlots[freeCount++] = slot;
        size--;
    }

    /** Changes the state of a live session, keeping the active count right. */
    public void state(int slot, byte newState) {
        int c = slot >>> CHUNK_SHIFT;
        int o = slot & CHUNK_MASK;
        byte old = state[c][o];
        if (old == ACTIVE && newState != ACTIVE) {
            activeCount--;
        } else if (old != ACTIVE && newState == ACTIVE) {
            activeCount++;
        }
        state[c][o] = newState;
    }

    // ---- iteration -----------------------------------------------------------------------------

    /** One past the highest slot ever used; iterate {@code 0..highWater()} and skip {@link #FREE} slots. */
    public int highWater() {
        return highWater;
    }

    /** First session of the NAS, or {@code -1}; continue with {@link #nextOfNas(int)}. */
    public int firstOfNas(int nas) {
        return nasHead.get(nas);
    }

    public int nextOfNas(int slot) {
        return next[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public int size() {
        return size;
    }

    public int activeCount() {
        return activeCount;
    }

    public int stoppedCount() {
        return size - activeCount;
    }

    /** Bytes held by the store's arrays (columns of allocated chunks + index). */
    public long footprintBytes() {
        long perSlot = 4L * 8 + 8L * 4 + 3 + 2; // 4 long, 8 int, 3 byte, 1 char columns
        return chunks * (long) CHUNK_SIZE * perSlot + index.length * 4L + freeSlots.length * 4L;
    }

    // ---- columns -------------------------------------------------------------------------------

    public long keyHi(int slot) {
        return keyHi[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public long keyLo(int slot) {
        return keyLo[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public int nasId(int slot) {
        return nasId[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public byte state(int slot) {
        return state[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public int statusType(int slot) {
        return statusType[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] & 0xFF;
    }

    public void statusType(int slot, int value) {
        statusType[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = (byte) value;
    }

    public byte flags(int slot) {
        return flags[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void flags(int slot, byte value) {
        flags[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = value;
    }

    /** Unsigned 32 bit value as {@code long}. */
    public long sessionTime(int slot) {
        return sessionTime[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] & 0xFFFF_FFFFL;
    }

    public void sessionTime(int slot, long value) {
        sessionTime[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = (int) value;
    }

    public long eventTimestamp(int slot) {
        return eventTimestamp[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] & 0xFFFF_FFFFL;
    }

    public void eventTimestamp(int slot, long value) {
        eventTimestamp[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = (int) value;
    }

    public long inputOctets(int slot) {
        return inputOctets[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void inputOctets(int slot, long value) {
        inputOctets[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = value;
    }

    public long outputOctets(int slot) {
        return outputOctets[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void outputOctets(int slot, long value) {
        outputOctets[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = value;
    }

    public int startKey(int slot) {
        return startKey[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void startKey(int slot, int value) {
        startKey[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = value;
    }

    /** Cluster time of the last applied event, in seconds. */
    public int lastSeen(int slot) {
        return lastSeen[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void lastSeen(int slot, int seconds) {
        lastSeen[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = seconds;
    }

    /** Cluster time in seconds until which a stopped session is kept, or 0. */
    /** Idle timeout of the session's NAS entry in minutes; 0 = the cluster's default. */
    public int idleMinutes(int slot) {
        return idleMinutes[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void idleMinutes(int slot, int minutes) {
        idleMinutes[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = (char) minutes;
    }

    public int tombstoneUntil(int slot) {
        return tombstoneUntil[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
    }

    public void tombstoneUntil(int slot, int seconds) {
        tombstoneUntil[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = seconds;
    }

    // ---- internals -----------------------------------------------------------------------------

    private int allocateSlot() {
        if (freeCount > 0) {
            return freeSlots[--freeCount];
        }
        int slot = highWater;
        if ((slot >>> CHUNK_SHIFT) >= chunks) {
            addChunk();
        }
        highWater++;
        return slot;
    }

    private void addChunk() {
        if (chunks == MAX_CHUNKS) {
            throw new IllegalStateException("session store full");
        }
        int c = chunks++;
        keyHi[c] = new long[CHUNK_SIZE];
        keyLo[c] = new long[CHUNK_SIZE];
        inputOctets[c] = new long[CHUNK_SIZE];
        outputOctets[c] = new long[CHUNK_SIZE];
        nasId[c] = new int[CHUNK_SIZE];
        sessionTime[c] = new int[CHUNK_SIZE];
        eventTimestamp[c] = new int[CHUNK_SIZE];
        startKey[c] = new int[CHUNK_SIZE];
        lastSeen[c] = new int[CHUNK_SIZE];
        tombstoneUntil[c] = new int[CHUNK_SIZE];
        prev[c] = new int[CHUNK_SIZE];
        next[c] = new int[CHUNK_SIZE];
        state[c] = new byte[CHUNK_SIZE];
        statusType[c] = new byte[CHUNK_SIZE];
        flags[c] = new byte[CHUNK_SIZE];
        idleMinutes[c] = new char[CHUNK_SIZE];
    }

    private int bucket(long hi) {
        long h = hi * 0x9E37_79B9_7F4A_7C15L;
        return (int) (h ^ (h >>> 32)) & indexMask;
    }

    private void growIndex() {
        int[] old = index;
        index = new int[old.length * 2];
        indexMask = index.length - 1;
        for (int entry : old) {
            if (entry != 0) {
                int slot = entry - 1;
                int i = bucket(keyHi(slot));
                while (index[i] != 0) {
                    i = (i + 1) & indexMask;
                }
                index[i] = entry;
            }
        }
    }

    /** Linear probing delete with backward shift, so lookups never need tombstones. */
    private void removeFromIndex(int slot, long hi) {
        int i = bucket(hi);
        while (index[i] != slot + 1) {
            i = (i + 1) & indexMask;
        }
        int hole = i;
        int j = i;
        while (true) {
            j = (j + 1) & indexMask;
            int entry = index[j];
            if (entry == 0) {
                break;
            }
            int home = bucket(keyHi(entry - 1));
            // move entry back if its home lies cyclically outside (hole, j]
            boolean between = hole <= j ? (home > hole && home <= j) : (home > hole || home <= j);
            if (!between) {
                index[hole] = entry;
                hole = j;
            }
        }
        index[hole] = 0;
    }

    private void linkNas(int slot, int nas) {
        int head = nasHead.get(nas);
        prev[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = NONE;
        next[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK] = head;
        if (head != NONE) {
            prev[head >>> CHUNK_SHIFT][head & CHUNK_MASK] = slot;
        }
        nasHead.put(nas, slot);
    }

    private void unlinkNas(int slot) {
        int p = prev[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
        int n = next[slot >>> CHUNK_SHIFT][slot & CHUNK_MASK];
        if (p != NONE) {
            next[p >>> CHUNK_SHIFT][p & CHUNK_MASK] = n;
        } else {
            int nas = nasId(slot);
            if (n == NONE) {
                nasHead.remove(nas);
            } else {
                nasHead.put(nas, n);
            }
        }
        if (n != NONE) {
            prev[n >>> CHUNK_SHIFT][n & CHUNK_MASK] = p;
        }
    }
}
