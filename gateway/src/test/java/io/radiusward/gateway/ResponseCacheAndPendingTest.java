/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetSocketAddress;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class ResponseCacheAndPendingTest {

    @Test
    void cacheStatesAndExpiry() {
        ResponseCache cache = new ResponseCache();
        long key = ResponseCache.key(0x0A000001, 1812, 7, 11, 22);
        assertThat(cache.get(key)).isEqualTo(ResponseCache.MISSING);
        cache.put(key, ResponseCache.PENDING, 100);
        cache.put(key, ResponseCache.COMMITTED, 300); // refreshed later
        cache.evict(150);
        assertThat(cache.get(key))
                .as("older ring entry must not evict the newer state")
                .isEqualTo(ResponseCache.COMMITTED);
        cache.evict(300);
        assertThat(cache.get(key)).isEqualTo(ResponseCache.MISSING);
        for (int i = 0; i < 5000; i++) {
            cache.put(ResponseCache.key(i, 1, 1, i, i), ResponseCache.PENDING, 1000 + i);
        }
        assertThat(cache.size()).isEqualTo(5000);
        cache.evict(3500);
        assertThat(cache.size()).isEqualTo(2499);
        cache.remove(ResponseCache.key(4999, 1, 1, 4999, 4999));
        assertThat(cache.size()).isEqualTo(2498);
        assertThat(ResponseCache.key(1, 2, 3, 4, 5)).isNotEqualTo(ResponseCache.key(1, 2, 4, 4, 5));
        long corr = (0x3FFF_FFFFL << 32) | 12345;
        long value = ResponseCache.pendingOf(corr);
        assertThat(ResponseCache.state(value)).isEqualTo(ResponseCache.PENDING);
        assertThat(ResponseCache.correlationId(value)).isEqualTo(corr);
        assertThat(ResponseCache.state(ResponseCache.COMMITTED)).isEqualTo(ResponseCache.COMMITTED);
    }

    @Test
    void pendingSlotsAndGenerations() {
        PendingTable table = new PendingTable(2);
        InetSocketAddress from = new InetSocketAddress("127.0.0.1", 1000);
        long a = table.allocate(1, 10, from, null, 5, true);
        long b = table.allocate(2, 11, from, null, 6, false);
        assertThat(table.allocate(3, 12, from, null, 7, false)).isEqualTo(-1);
        int slotA = table.slotOf(a);
        assertThat(table.identifier(slotA)).isEqualTo(5);
        assertThat(table.withMessageAuthenticator(slotA)).isTrue();
        assertThat(table.cacheKey(slotA)).isEqualTo(1);
        table.release(slotA);
        assertThat(table.slotOf(a)).as("released").isEqualTo(-1);
        long c = table.allocate(4, 13, from, null, 8, false);
        assertThat((int) c).as("slot reused").isEqualTo(slotA);
        assertThat(table.slotOf(a))
                .as("old generation does not match the reused slot")
                .isEqualTo(-1);
        assertThat(table.slotOf(c)).isEqualTo(slotA);
        assertThat(table.slotOf(b)).isGreaterThanOrEqualTo(0);
        assertThat(table.slotOf(-5)).isEqualTo(-1);
        assertThat(table.size()).isEqualTo(2);
    }

    @Test
    void storedCommands() {
        PendingTable table = new PendingTable(2);
        int slot = (int) table.allocate(1, 1, null, null, 1, false);
        UnsafeBuffer command = new UnsafeBuffer(new byte[2048]);
        command.putByte(0, (byte) 42);
        assertThat(table.command(slot, command, 0, 100)).isTrue();
        assertThat(table.commandLength(slot)).isEqualTo(100);
        assertThat(table.commands().getByte(table.commandOffset(slot))).isEqualTo((byte) 42);
        assertThat(table.command(slot, command, 0, PendingTable.COMMAND_CAPACITY + 1))
                .isFalse();
        assertThat(table.commandLength(slot)).as("too large: nothing kept").isZero();
    }

    @Test
    void proxyStateCapacity() {
        PendingTable table = new PendingTable(1);
        int slot = (int) table.allocate(1, 1, null, null, 1, false);
        UnsafeBuffer attr = new UnsafeBuffer(new byte[255]);
        attr.putByte(0, (byte) 33);
        attr.putByte(1, (byte) 200);
        assertThat(table.addProxyState(slot, attr, 0, 200)).isTrue();
        assertThat(table.addProxyState(slot, attr, 0, 100)).isFalse();
        assertThat(table.proxyStateLength(slot)).isEqualTo(200);
    }
}
