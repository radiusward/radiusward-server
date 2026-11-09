/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.junit.jupiter.api.Test;

class SessionStoreTest {

    private final SessionStore store = new SessionStore();

    @Test
    void insertFindRemove() {
        int a = store.insert(1, 2, 10, SessionStore.ACTIVE);
        int b = store.insert(1, 3, 10, SessionStore.STOPPED); // same hi, different lo
        assertThat(store.find(1, 2)).isEqualTo(a);
        assertThat(store.find(1, 3)).isEqualTo(b);
        assertThat(store.find(9, 9)).isEqualTo(-1);
        assertThat(store.size()).isEqualTo(2);
        assertThat(store.activeCount()).isEqualTo(1);
        assertThat(store.stoppedCount()).isEqualTo(1);

        store.remove(a);
        assertThat(store.find(1, 2)).isEqualTo(-1);
        assertThat(store.find(1, 3)).isEqualTo(b);
        assertThat(store.activeCount()).isZero();
        assertThat(store.state(a)).isEqualTo(SessionStore.FREE);

        int c = store.insert(5, 5, 11, SessionStore.ACTIVE);
        assertThat(c).as("freed slot is reused").isEqualTo(a);
    }

    @Test
    void columnsRoundTripIncludingUnsigned() {
        int s = store.insert(7, 8, 3, SessionStore.ACTIVE);
        store.statusType(s, 3);
        store.flags(s, (byte) 3);
        store.sessionTime(s, 0xFFFF_FFFFL);
        store.eventTimestamp(s, 3_000_000_000L);
        store.inputOctets(s, Long.MAX_VALUE);
        store.outputOctets(s, 5);
        store.startKey(s, -9);
        store.lastSeen(s, 100);
        store.tombstoneUntil(s, 200);
        assertThat(store.keyHi(s)).isEqualTo(7);
        assertThat(store.keyLo(s)).isEqualTo(8);
        assertThat(store.nasId(s)).isEqualTo(3);
        assertThat(store.statusType(s)).isEqualTo(3);
        assertThat(store.flags(s)).isEqualTo((byte) 3);
        assertThat(store.sessionTime(s)).isEqualTo(0xFFFF_FFFFL);
        assertThat(store.eventTimestamp(s)).isEqualTo(3_000_000_000L);
        assertThat(store.inputOctets(s)).isEqualTo(Long.MAX_VALUE);
        assertThat(store.outputOctets(s)).isEqualTo(5);
        assertThat(store.startKey(s)).isEqualTo(-9);
        assertThat(store.lastSeen(s)).isEqualTo(100);
        assertThat(store.tombstoneUntil(s)).isEqualTo(200);
    }

    @Test
    void randomizedAgainstHashMap() {
        Random random = new Random(42);
        Map<Long, Integer> reference = new HashMap<>();
        List<Long> keys = new ArrayList<>();
        for (int i = 0; i < 200_000; i++) {
            if (keys.isEmpty() || random.nextInt(3) > 0) {
                long hi = random.nextInt(50_000); // many collisions in the index on purpose
                long lo = random.nextLong();
                long key = hi * 31 + lo;
                if (!reference.containsKey(key) && store.find(hi, lo) < 0) {
                    int slot = store.insert(hi, lo, (int) (hi % 17), SessionStore.ACTIVE);
                    reference.put(key, slot);
                    keys.add(key);
                    keyParts.put(key, new long[] {hi, lo});
                }
            } else {
                long key = keys.remove(random.nextInt(keys.size()));
                long[] parts = keyParts.remove(key);
                int slot = reference.remove(key);
                assertThat(store.find(parts[0], parts[1])).isEqualTo(slot);
                store.remove(slot);
                assertThat(store.find(parts[0], parts[1])).isEqualTo(-1);
            }
        }
        assertThat(store.size()).isEqualTo(reference.size());
        for (Map.Entry<Long, Integer> e : reference.entrySet()) {
            long[] parts = keyParts.get(e.getKey());
            assertThat(store.find(parts[0], parts[1])).isEqualTo(e.getValue());
        }
    }

    private final Map<Long, long[]> keyParts = new HashMap<>();

    @Test
    void perNasLists() {
        int a = store.insert(1, 1, 7, SessionStore.ACTIVE);
        int b = store.insert(2, 2, 7, SessionStore.ACTIVE);
        int c = store.insert(3, 3, 7, SessionStore.ACTIVE);
        store.insert(4, 4, 8, SessionStore.ACTIVE);
        assertThat(nasSlots(7)).containsExactlyInAnyOrder(a, b, c);
        store.remove(b); // middle
        assertThat(nasSlots(7)).containsExactlyInAnyOrder(a, c);
        store.remove(c); // head
        store.remove(a); // last
        assertThat(nasSlots(7)).isEmpty();
        assertThat(nasSlots(8)).hasSize(1);
        assertThat(store.firstOfNas(99)).isEqualTo(-1);
    }

    private List<Integer> nasSlots(int nas) {
        List<Integer> slots = new ArrayList<>();
        for (int s = store.firstOfNas(nas); s >= 0; s = store.nextOfNas(s)) {
            slots.add(s);
        }
        return slots;
    }

    @Test
    void stateTransitionsKeepCounts() {
        int s = store.insert(1, 1, 1, SessionStore.ACTIVE);
        store.state(s, SessionStore.STOPPED);
        assertThat(store.activeCount()).isZero();
        store.state(s, SessionStore.ACTIVE);
        assertThat(store.activeCount()).isEqualTo(1);
        store.state(s, SessionStore.ACTIVE);
        assertThat(store.activeCount()).isEqualTo(1);
    }

    @Test
    void footprintFor500kSessions() {
        for (int i = 0; i < 500_000; i++) {
            store.insert(i * 0x9E3779B97F4A7C15L, i, i % 1000, SessionStore.ACTIVE);
        }
        long bytes = store.footprintBytes();
        // state version 6 added the user and device of a session (16 bytes, simultaneous use)
        assertThat(bytes).as("bytes for 500k sessions").isLessThanOrEqualTo(52L << 20);
        assertThat(bytes / 500_000.0).as("bytes per session").isLessThan(105.0);
        assertThat(store.find(499_999 * 0x9E3779B97F4A7C15L, 499_999)).isGreaterThanOrEqualTo(0);
    }
}
