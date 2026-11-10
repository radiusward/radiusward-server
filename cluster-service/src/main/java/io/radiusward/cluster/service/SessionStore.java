/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import org.agrona.BufferUtil;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.Int2IntHashMap;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Accounting sessions in off-heap records (ADR 0012, 0036): no object per session and nothing per session on the heap,
 * a 4 byte open-addressing index slot, allocation only when a new chunk or a larger index is needed. A chunk of
 * {@value #CHUNK_SIZE} slots holds a 72 byte core record per session (what the exporter's replica needs as well),
 * and — allocated only once a chunk uses them — a 32 byte member record (user, device, first event: simultaneous use
 * and CoA) and the 64 byte identifying attributes. Off-heap, they need no garbage-collector headroom: a small member
 * holds its 2M sessions in 1 GiB (ADR 0004).
 *
 * <p>Freed slots are reused LIFO. A session is identified by its 128 bit key. Every session is also linked into a
 * per-NAS list so Accounting-On/Off can close all sessions of a NAS.
 *
 * <p>An active session with a user (state version 6, simultaneous use) is also linked into its user's list, found
 * through an index by user: the distinct devices (Calling-Station-Id) a user has online are counted along it, every
 * session without a device on its own. The lists follow every state change and are rebuilt when sessions are
 * restored, so they are not part of the snapshot.
 *
 * <p>Deterministic: the same sequence of calls produces the same slots and the same iteration order, which the
 * replicated state machine relies on. Not thread-safe.
 */
public final class SessionStore {

    public static final byte FREE = 0;
    public static final byte ACTIVE = 1;
    public static final byte STOPPED = 2;

    /** Presence bits in {@link #flags(int)}. */
    public static final byte HAS_SESSION_TIME = 1;

    public static final byte HAS_EVENT_TIMESTAMP = 2;

    /** Bytes per session for its identifying attributes: a length byte, then RADIUS attributes (ADR 0036). */
    public static final int IDENTITY_SIZE = 64;

    static final int CHUNK_SHIFT = 14;
    static final int CHUNK_SIZE = 1 << CHUNK_SHIFT;
    private static final int CHUNK_MASK = CHUNK_SIZE - 1;
    private static final int MAX_CHUNKS = 1 << 14; // 268M slots
    private static final int NONE = -1;

    // core record
    private static final int CORE = 72;
    private static final int KEY_HI = 0;
    private static final int KEY_LO = 8;
    private static final int INPUT_OCTETS = 16;
    private static final int OUTPUT_OCTETS = 24;
    private static final int NAS_ID = 32;
    private static final int SESSION_TIME = 36;
    private static final int EVENT_TIMESTAMP = 40;
    private static final int START_KEY = 44;
    private static final int LAST_SEEN = 48;
    private static final int TOMBSTONE_UNTIL = 52;
    private static final int PREV = 56;
    private static final int NEXT = 60;
    private static final int IDLE_MINUTES = 64;
    private static final int STATE = 66;
    private static final int STATUS_TYPE = 67;
    private static final int FLAGS = 68;

    // member record
    private static final int MEMBER = 32;
    private static final int USER_KEY = 0;
    private static final int DEVICE_KEY = 8;
    private static final int FIRST_SEEN = 16;
    private static final int USER_NEXT = 20;
    private static final int USER_PREV = 24;

    private final UnsafeBuffer[] core = new UnsafeBuffer[MAX_CHUNKS];
    private final UnsafeBuffer[] member = new UnsafeBuffer[MAX_CHUNKS];
    private final UnsafeBuffer[] identity = new UnsafeBuffer[MAX_CHUNKS];

    private int chunks;
    private int highWater; // slots ever handed out
    private int[] freeSlots = new int[64];
    private int freeCount;
    private int size;
    private int activeCount;

    private int[] index; // slot + 1, 0 = empty
    private int indexMask;

    private final Int2IntHashMap nasHead = new Int2IntHashMap(NONE);

    /** Head slot + 1 of each user's list of active sessions, by user key; 0 = empty. Never iterated. */
    private int[] userIndex = new int[1 << 10];

    private int userIndexMask = userIndex.length - 1;
    private int users;
    private long[] seen = new long[16]; // devices met while counting

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
            if (keyHi(slot) == hi && keyLo(slot) == lo) {
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
        UnsafeBuffer b = core[slot >>> CHUNK_SHIFT];
        int at = (slot & CHUNK_MASK) * CORE;
        b.setMemory(at, CORE, (byte) 0);
        b.putLong(at + KEY_HI, hi);
        b.putLong(at + KEY_LO, lo);
        b.putInt(at + NAS_ID, nas);
        b.putByte(at + STATE, initialState);
        UnsafeBuffer m = member[slot >>> CHUNK_SHIFT];
        if (m != null) {
            m.setMemory((slot & CHUNK_MASK) * MEMBER, MEMBER, (byte) 0);
        }
        UnsafeBuffer id = identity[slot >>> CHUNK_SHIFT];
        if (id != null) {
            id.putByte((slot & CHUNK_MASK) * IDENTITY_SIZE, (byte) 0);
        }
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
        removeFromIndex(slot, keyHi(slot));
        unlinkNas(slot);
        if (state(slot) == ACTIVE) {
            activeCount--;
            untrack(slot);
        }
        putByte(slot, STATE, FREE);
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
        byte old = state(slot);
        if (old == ACTIVE && newState != ACTIVE) {
            activeCount--;
            untrack(slot);
        } else if (old != ACTIVE && newState == ACTIVE) {
            activeCount++;
            putByte(slot, STATE, newState);
            track(slot);
            return;
        }
        putByte(slot, STATE, newState);
    }

    // ---- users (simultaneous use) --------------------------------------------------------------

    /**
     * Sets the session's user and device.
     *
     * @return whether an active session newly counts for this user and device (it did not before)
     */
    public boolean user(int slot, long user, long device) {
        if (userKey(slot) == user && deviceKey(slot) == device) {
            return false;
        }
        boolean active = state(slot) == ACTIVE;
        if (active) {
            untrack(slot);
        }
        UnsafeBuffer m = memberRecord(slot);
        int at = (slot & CHUNK_MASK) * MEMBER;
        m.putLong(at + USER_KEY, user);
        m.putLong(at + DEVICE_KEY, device);
        if (active) {
            track(slot);
        }
        return active && user != 0;
    }

    public long userKey(int slot) {
        UnsafeBuffer m = member[slot >>> CHUNK_SHIFT];
        return m == null ? 0 : m.getLong((slot & CHUNK_MASK) * MEMBER + USER_KEY);
    }

    public long deviceKey(int slot) {
        UnsafeBuffer m = member[slot >>> CHUNK_SHIFT];
        return m == null ? 0 : m.getLong((slot & CHUNK_MASK) * MEMBER + DEVICE_KEY);
    }

    /** Distinct devices the user has online (sessions without a device each count once). */
    public int devicesOnline(long user) {
        return devicesOnline(user, Integer.MAX_VALUE);
    }

    /** As above, counting no further than {@code limit}: all a limit check needs, however many sessions. */
    public int devicesOnline(long user, int limit) {
        int count = 0;
        int distinct = 0;
        for (int s = userHead(user); s != NONE && count < limit; s = userNext(s)) {
            long device = deviceKey(s);
            if (device == 0) {
                count++;
                continue;
            }
            boolean known = false;
            for (int k = 0; k < distinct && !known; k++) {
                known = seen[k] == device;
            }
            if (!known) {
                if (distinct == seen.length) {
                    seen = java.util.Arrays.copyOf(seen, distinct * 2);
                }
                seen[distinct++] = device;
                count++;
            }
        }
        return count;
    }

    /** Whether the user has an active session on this device ({@code device != 0}). */
    public boolean online(long user, long device) {
        if (device == 0) {
            return false;
        }
        for (int s = userHead(user); s != NONE; s = userNext(s)) {
            if (deviceKey(s) == device) {
                return true;
            }
        }
        return false;
    }

    /** Links an active session into its user's list. */
    private void track(int slot) {
        long user = userKey(slot);
        if (user == 0) {
            return;
        }
        if ((users + 1) * 2L > userIndex.length) {
            growUserIndex();
        }
        UnsafeBuffer m = member[slot >>> CHUNK_SHIFT];
        int at = (slot & CHUNK_MASK) * MEMBER;
        int i = userBucket(user);
        while (userIndex[i] != 0) {
            int head = userIndex[i] - 1;
            if (userKey(head) == user) {
                m.putInt(at + USER_NEXT, head);
                m.putInt(at + USER_PREV, NONE);
                putUserLink(head, USER_PREV, slot);
                userIndex[i] = slot + 1;
                return;
            }
            i = (i + 1) & userIndexMask;
        }
        m.putInt(at + USER_NEXT, NONE);
        m.putInt(at + USER_PREV, NONE);
        userIndex[i] = slot + 1;
        users++;
    }

    /** Takes an active session out of its user's list. */
    private void untrack(int slot) {
        long user = userKey(slot);
        if (user == 0) {
            return;
        }
        int prev = userLink(slot, USER_PREV);
        int next = userLink(slot, USER_NEXT);
        if (prev != NONE) {
            putUserLink(prev, USER_NEXT, next);
        } else {
            int i = userBucket(user);
            while (userIndex[i] != slot + 1) {
                i = (i + 1) & userIndexMask;
            }
            if (next != NONE) {
                userIndex[i] = next + 1;
            } else {
                removeUserEntry(i);
                users--;
            }
        }
        if (next != NONE) {
            putUserLink(next, USER_PREV, prev);
        }
    }

    private int userHead(long user) {
        if (user == 0) {
            return NONE;
        }
        for (int i = userBucket(user); userIndex[i] != 0; i = (i + 1) & userIndexMask) {
            int head = userIndex[i] - 1;
            if (userKey(head) == user) {
                return head;
            }
        }
        return NONE;
    }

    private int userNext(int slot) {
        return userLink(slot, USER_NEXT);
    }

    private int userLink(int slot, int field) {
        return member[slot >>> CHUNK_SHIFT].getInt((slot & CHUNK_MASK) * MEMBER + field);
    }

    private void putUserLink(int slot, int field, int value) {
        member[slot >>> CHUNK_SHIFT].putInt((slot & CHUNK_MASK) * MEMBER + field, value);
    }

    private int userBucket(long user) {
        long h = user * 0xC2B2_AE3D_27D4_EB4FL;
        return (int) (h ^ (h >>> 32)) & userIndexMask;
    }

    private void growUserIndex() {
        int[] old = userIndex;
        userIndex = new int[old.length * 2];
        userIndexMask = userIndex.length - 1;
        for (int entry : old) {
            if (entry != 0) {
                int i = userBucket(userKey(entry - 1));
                while (userIndex[i] != 0) {
                    i = (i + 1) & userIndexMask;
                }
                userIndex[i] = entry;
            }
        }
    }

    /** Linear probing delete with backward shift. */
    private void removeUserEntry(int i) {
        int hole = i;
        int j = i;
        while (true) {
            j = (j + 1) & userIndexMask;
            int entry = userIndex[j];
            if (entry == 0) {
                break;
            }
            int home = userBucket(userKey(entry - 1));
            boolean between = hole <= j ? (home > hole && home <= j) : (home > hole || home <= j);
            if (!between) {
                userIndex[hole] = entry;
                hole = j;
            }
        }
        userIndex[hole] = 0;
    }

    /** One key for a user's device. */
    static long pair(long user, long device) {
        long h = (user ^ Long.rotateLeft(device, 29)) * 0x9E37_79B9_7F4A_7C15L;
        return h ^ (h >>> 31);
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
        return getInt(slot, NEXT);
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

    /** Bytes held by the store: records of allocated chunks (off-heap), indexes and free list. */
    public long footprintBytes() {
        long bytes = index.length * 4L + userIndex.length * 4L + freeSlots.length * 4L;
        for (int c = 0; c < chunks; c++) {
            bytes += core[c].capacity();
            bytes += member[c] == null ? 0 : member[c].capacity();
            bytes += identity[c] == null ? 0 : identity[c].capacity();
        }
        return bytes;
    }

    // ---- fields --------------------------------------------------------------------------------

    public long keyHi(int slot) {
        return getLong(slot, KEY_HI);
    }

    public long keyLo(int slot) {
        return getLong(slot, KEY_LO);
    }

    public int nasId(int slot) {
        return getInt(slot, NAS_ID);
    }

    public byte state(int slot) {
        return core[slot >>> CHUNK_SHIFT].getByte((slot & CHUNK_MASK) * CORE + STATE);
    }

    public int statusType(int slot) {
        return core[slot >>> CHUNK_SHIFT].getByte((slot & CHUNK_MASK) * CORE + STATUS_TYPE) & 0xFF;
    }

    public void statusType(int slot, int value) {
        putByte(slot, STATUS_TYPE, (byte) value);
    }

    public byte flags(int slot) {
        return core[slot >>> CHUNK_SHIFT].getByte((slot & CHUNK_MASK) * CORE + FLAGS);
    }

    public void flags(int slot, byte value) {
        putByte(slot, FLAGS, value);
    }

    /** Unsigned 32 bit value as {@code long}. */
    public long sessionTime(int slot) {
        return getInt(slot, SESSION_TIME) & 0xFFFF_FFFFL;
    }

    public void sessionTime(int slot, long value) {
        putInt(slot, SESSION_TIME, (int) value);
    }

    public long eventTimestamp(int slot) {
        return getInt(slot, EVENT_TIMESTAMP) & 0xFFFF_FFFFL;
    }

    public void eventTimestamp(int slot, long value) {
        putInt(slot, EVENT_TIMESTAMP, (int) value);
    }

    public long inputOctets(int slot) {
        return getLong(slot, INPUT_OCTETS);
    }

    public void inputOctets(int slot, long value) {
        putLong(slot, INPUT_OCTETS, value);
    }

    public long outputOctets(int slot) {
        return getLong(slot, OUTPUT_OCTETS);
    }

    public void outputOctets(int slot, long value) {
        putLong(slot, OUTPUT_OCTETS, value);
    }

    public int startKey(int slot) {
        return getInt(slot, START_KEY);
    }

    public void startKey(int slot, int value) {
        putInt(slot, START_KEY, value);
    }

    /** Cluster time of the last applied event, in seconds. */
    public int lastSeen(int slot) {
        return getInt(slot, LAST_SEEN);
    }

    public void lastSeen(int slot, int seconds) {
        putInt(slot, LAST_SEEN, seconds);
    }

    /** Idle timeout of the session's NAS entry in minutes; 0 = the cluster's default. */
    public int idleMinutes(int slot) {
        return core[slot >>> CHUNK_SHIFT].getChar((slot & CHUNK_MASK) * CORE + IDLE_MINUTES);
    }

    public void idleMinutes(int slot, int minutes) {
        core[slot >>> CHUNK_SHIFT].putChar((slot & CHUNK_MASK) * CORE + IDLE_MINUTES, (char) minutes);
    }

    /** Cluster time in seconds until which a stopped session is kept, or 0. */
    public int tombstoneUntil(int slot) {
        return getInt(slot, TOMBSTONE_UNTIL);
    }

    public void tombstoneUntil(int slot, int seconds) {
        putInt(slot, TOMBSTONE_UNTIL, seconds);
    }

    /** Cluster time in seconds of the session's first event (state version 7; 0 before). */
    public int firstSeen(int slot) {
        UnsafeBuffer m = member[slot >>> CHUNK_SHIFT];
        return m == null ? 0 : m.getInt((slot & CHUNK_MASK) * MEMBER + FIRST_SEEN);
    }

    public void firstSeen(int slot, int seconds) {
        memberRecord(slot).putInt((slot & CHUNK_MASK) * MEMBER + FIRST_SEEN, seconds);
    }

    /** Length of the session's identifying attributes; 0 = none (ADR 0036). */
    public int identityLength(int slot) {
        UnsafeBuffer chunk = identity[slot >>> CHUNK_SHIFT];
        return chunk == null ? 0 : chunk.getByte((slot & CHUNK_MASK) * IDENTITY_SIZE) & 0xFF;
    }

    /** Copies the session's identifying attributes to {@code dst}; returns their length. */
    public int identity(int slot, MutableDirectBuffer dst, int offset) {
        UnsafeBuffer chunk = identity[slot >>> CHUNK_SHIFT];
        if (chunk == null) {
            return 0;
        }
        int at = (slot & CHUNK_MASK) * IDENTITY_SIZE;
        int length = chunk.getByte(at) & 0xFF;
        dst.putBytes(offset, chunk, at + 1, length);
        return length;
    }

    /** Replaces the session's identifying attributes; at most {@code IDENTITY_SIZE - 1} bytes. */
    public void identity(int slot, DirectBuffer src, int offset, int length) {
        if (length < 0 || length >= IDENTITY_SIZE) {
            throw new IllegalArgumentException("identity of " + length + " bytes");
        }
        UnsafeBuffer chunk = identity[slot >>> CHUNK_SHIFT];
        if (chunk == null) {
            chunk = identity[slot >>> CHUNK_SHIFT] = offHeap(CHUNK_SIZE * IDENTITY_SIZE);
        }
        int at = (slot & CHUNK_MASK) * IDENTITY_SIZE;
        chunk.putByte(at, (byte) length);
        chunk.putBytes(at + 1, src, offset, length);
    }

    /** A digest of the identifying attributes, for the state machine's cross-member check. */
    public long identityHash(int slot) {
        UnsafeBuffer chunk = identity[slot >>> CHUNK_SHIFT];
        if (chunk == null) {
            return 0;
        }
        int at = (slot & CHUNK_MASK) * IDENTITY_SIZE;
        long h = 0x9E37_79B9_7F4A_7C15L;
        for (int i = 0, n = (chunk.getByte(at) & 0xFF) + 1; i < n; i++) {
            h = (h ^ chunk.getByte(at + i)) * 0x100_0000_01B3L;
        }
        return h;
    }

    // ---- internals -----------------------------------------------------------------------------

    private long getLong(int slot, int field) {
        return core[slot >>> CHUNK_SHIFT].getLong((slot & CHUNK_MASK) * CORE + field);
    }

    private void putLong(int slot, int field, long value) {
        core[slot >>> CHUNK_SHIFT].putLong((slot & CHUNK_MASK) * CORE + field, value);
    }

    private int getInt(int slot, int field) {
        return core[slot >>> CHUNK_SHIFT].getInt((slot & CHUNK_MASK) * CORE + field);
    }

    private void putInt(int slot, int field, int value) {
        core[slot >>> CHUNK_SHIFT].putInt((slot & CHUNK_MASK) * CORE + field, value);
    }

    private void putByte(int slot, int field, byte value) {
        core[slot >>> CHUNK_SHIFT].putByte((slot & CHUNK_MASK) * CORE + field, value);
    }

    /** The slot's member record, its chunk allocated on first use (never in the exporter's replica). */
    private UnsafeBuffer memberRecord(int slot) {
        UnsafeBuffer m = member[slot >>> CHUNK_SHIFT];
        if (m == null) {
            m = member[slot >>> CHUNK_SHIFT] = offHeap(CHUNK_SIZE * MEMBER);
        }
        return m;
    }

    /** Zeroed off-heap memory (direct buffers are zero-filled). */
    private static UnsafeBuffer offHeap(int bytes) {
        return new UnsafeBuffer(BufferUtil.allocateDirectAligned(bytes, 64));
    }

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
        core[chunks++] = offHeap(CHUNK_SIZE * CORE);
        // member and identity records: allocated with their chunk's first use, so stores that keep none (the
        // exporter's replica, a cluster below state version 6 or 7) do not pay for them
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
        putInt(slot, PREV, NONE);
        putInt(slot, NEXT, head);
        if (head != NONE) {
            putInt(head, PREV, slot);
        }
        nasHead.put(nas, slot);
    }

    private void unlinkNas(int slot) {
        int p = getInt(slot, PREV);
        int n = getInt(slot, NEXT);
        if (p != NONE) {
            putInt(p, NEXT, n);
        } else {
            int nas = nasId(slot);
            if (n == NONE) {
                nasHead.remove(nas);
            } else {
                nasHead.put(nas, n);
            }
        }
        if (n != NONE) {
            putInt(n, PREV, p);
        }
    }
}
