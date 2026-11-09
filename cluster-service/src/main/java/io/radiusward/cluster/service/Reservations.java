/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import java.util.Arrays;
import org.agrona.collections.Long2LongHashMap;

/**
 * Places held for devices that were granted an Access-Accept under a simultaneous-use limit but have not started
 * accounting yet (state version 6, ADR 0023). A reservation ends with the device's Accounting-Start or at its expiry.
 *
 * <p>Columns of primitive arrays, a per-user doubly linked list and an Agrona map from user to the list head; freed
 * slots are reused LIFO. Deterministic: no decision depends on slot numbers or list order (the reservation used up
 * by a Start is chosen by expiry, then device), so a replica restored from a snapshot decides like one that ran from
 * the start. Not thread-safe.
 */
public final class Reservations {

    private static final int NONE = -1;

    private final int capacity;
    private long[] user = new long[0];
    private long[] device = new long[0];
    private long[] expiry = new long[0];
    private int[] prev = new int[0];
    private int[] next = new int[0];
    private boolean[] used = new boolean[0];
    private int[] freeSlots = new int[0];
    private int freeCount;
    private int highWater;
    private int size;
    private final Long2LongHashMap head = new Long2LongHashMap(NONE);

    public Reservations(int capacity) {
        this.capacity = capacity;
    }

    /** Reservations of {@code user} not expired at {@code now} whose device is not already online. */
    int live(long user, long now, SessionStore store) {
        int n = 0;
        for (int s = (int) head.get(user); s != NONE; s = next[s]) {
            if (expiry[s] > now && !store.online(user, device[s])) {
                n++;
            }
        }
        return n;
    }

    /** Extends the live reservation of this device ({@code device != 0}); whether there was one. */
    boolean refresh(long user, long device, long newExpiry, long now) {
        for (int s = (int) head.get(user); s != NONE; s = next[s]) {
            if (this.device[s] == device && expiry[s] > now) {
                expiry[s] = Math.max(expiry[s], newExpiry);
                return true;
            }
        }
        return false;
    }

    /** Adds a reservation; {@code false} when full. */
    boolean add(long user, long device, long expiry) {
        if (size >= capacity) {
            return false;
        }
        insert(user, device, expiry);
        return true;
    }

    private void insert(long user, long device, long expiry) {
        int s = allocate();
        this.user[s] = user;
        this.device[s] = device;
        this.expiry[s] = expiry;
        used[s] = true;
        int first = (int) head.get(user);
        prev[s] = NONE;
        next[s] = first;
        if (first != NONE) {
            prev[first] = s;
        }
        head.put(user, s);
        size++;
    }

    /**
     * A session of the user came online: ends the reservation it used. A known device ends its own reservation, or
     * else one made without a device; an unknown device ends the reservation that expires first.
     *
     * @return whether a reservation ended
     */
    boolean consume(long user, long device, long now) {
        int best = NONE;
        for (int s = (int) head.get(user); s != NONE; s = next[s]) {
            if (expiry[s] <= now) {
                continue;
            }
            if (device != 0 && this.device[s] == device) {
                best = s;
                break;
            }
            if ((device == 0 || this.device[s] == 0) && (best == NONE || earlier(s, best))) {
                best = s;
            }
        }
        if (best == NONE) {
            return false;
        }
        remove(best);
        return true;
    }

    private boolean earlier(int a, int b) {
        return expiry[a] != expiry[b] ? expiry[a] < expiry[b] : Long.compareUnsigned(device[a], device[b]) < 0;
    }

    /** Removes expired reservations, in slot order; returns how many. */
    int sweep(long now) {
        int removed = 0;
        for (int s = 0; s < highWater; s++) {
            if (used[s] && expiry[s] <= now) {
                remove(s);
                removed++;
            }
        }
        return removed;
    }

    private void remove(int s) {
        if (prev[s] != NONE) {
            next[prev[s]] = next[s];
        } else if (next[s] != NONE) {
            head.put(user[s], next[s]);
        } else {
            head.remove(user[s]);
        }
        if (next[s] != NONE) {
            prev[next[s]] = prev[s];
        }
        used[s] = false;
        if (freeCount == freeSlots.length) {
            freeSlots = Arrays.copyOf(freeSlots, Math.max(16, freeSlots.length * 2));
        }
        freeSlots[freeCount++] = s;
        size--;
    }

    private int allocate() {
        if (freeCount > 0) {
            return freeSlots[--freeCount];
        }
        if (highWater == user.length) {
            int grown = Math.max(64, user.length * 2);
            user = Arrays.copyOf(user, grown);
            device = Arrays.copyOf(device, grown);
            expiry = Arrays.copyOf(expiry, grown);
            prev = Arrays.copyOf(prev, grown);
            next = Arrays.copyOf(next, grown);
            used = Arrays.copyOf(used, grown);
        }
        return highWater++;
    }

    // ---- iteration and snapshots ------------------------------------------------------------------

    public int size() {
        return size;
    }

    /** One past the highest slot used; iterate {@code 0..highWater()} and skip slots that are not {@link #used}. */
    public int highWater() {
        return highWater;
    }

    public boolean used(int slot) {
        return used[slot];
    }

    public long user(int slot) {
        return user[slot];
    }

    public long device(int slot) {
        return device[slot];
    }

    public long expiry(int slot) {
        return expiry[slot];
    }

    /** Restores one reservation from a snapshot (even above a capacity lowered since). */
    public void restore(long user, long device, long expiry) {
        insert(user, device, expiry);
    }
}
