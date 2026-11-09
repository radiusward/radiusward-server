/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.RadiusPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import org.agrona.BufferUtil;
import org.agrona.concurrent.ManyToManyConcurrentArrayQueue;
import org.agrona.concurrent.ManyToOneConcurrentArrayQueue;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The fixed set of Access-Requests between the socket thread and the workers. A slot holds the request bytes, its
 * source and NAS entry, and the reply a worker wrote. The socket thread takes free slots and offers them to
 * {@link #work}; a worker polls one, decides it and offers it to {@link #done}; the socket thread sends the reply
 * and frees the slot. The queues order the writes (a slot belongs to one thread at a time). Allocated once.
 */
final class AccessSlots {

    final int capacity;
    final UnsafeBuffer requests;
    final int[] requestLength;
    final InetSocketAddress[] source;
    final long[] route; // RadsecLink.UDP, or the RadSec connection to answer on
    final NasClient[] nas;
    final long[] cacheKey;
    final ByteBuffer[] replies; // direct, for DatagramChannel.send
    final UnsafeBuffer[] replyViews;
    final int[] replyLength; // 0: no answer
    final ManyToManyConcurrentArrayQueue<Integer> work;
    final ManyToOneConcurrentArrayQueue<Integer> done;
    final Integer[] ids; // boxed once: queues hold references, nothing is boxed per request

    private final int[] free;
    private int freeCount;

    AccessSlots(int capacity) {
        this.capacity = capacity;
        this.requests = new UnsafeBuffer(new byte[capacity * RadiusPacket.MAX_LENGTH]);
        this.requestLength = new int[capacity];
        this.source = new InetSocketAddress[capacity];
        this.route = new long[capacity];
        this.nas = new NasClient[capacity];
        this.cacheKey = new long[capacity];
        this.replies = new ByteBuffer[capacity];
        this.replyViews = new UnsafeBuffer[capacity];
        this.replyLength = new int[capacity];
        ByteBuffer all = BufferUtil.allocateDirectAligned(capacity * RadiusPacket.MAX_LENGTH, 64);
        for (int i = 0; i < capacity; i++) {
            replies[i] = all.slice(i * RadiusPacket.MAX_LENGTH, RadiusPacket.MAX_LENGTH);
            replyViews[i] = new UnsafeBuffer(replies[i]);
        }
        this.work = new ManyToManyConcurrentArrayQueue<>(capacity);
        this.done = new ManyToOneConcurrentArrayQueue<>(capacity);
        this.ids = new Integer[capacity];
        this.free = new int[capacity];
        for (int i = 0; i < capacity; i++) {
            ids[i] = i; // Integer.valueOf caches only small values: these are created here, once
            free[i] = capacity - 1 - i;
        }
        this.freeCount = capacity;
    }

    /** A free slot, or -1 (socket thread only). */
    int allocate() {
        return freeCount == 0 ? -1 : free[--freeCount];
    }

    /** Returns a slot (socket thread only). */
    void release(int slot) {
        source[slot] = null;
        nas[slot] = null;
        free[freeCount++] = slot;
    }

    int inUse() {
        return capacity - freeCount;
    }

    static int requestOffset(int slot) {
        return slot * RadiusPacket.MAX_LENGTH;
    }
}
