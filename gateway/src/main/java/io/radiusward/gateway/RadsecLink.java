/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import org.agrona.BufferUtil;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.OneToOneRingBuffer;
import org.agrona.concurrent.ringbuffer.RingBuffer;
import org.agrona.concurrent.ringbuffer.RingBufferDescriptor;

/**
 * Between the {@link RadsecAgent} and the agents that decide packets (ADR 0034): a request read from a TLS connection
 * goes to the {@link AuthAgent} or the {@link UdpAgent} as if it were a datagram, with its route and NAS entry; their
 * reply comes back with the route. A route names a connection and its generation, so a late reply to a closed
 * connection is never written into the next one using its place. One producer and one consumer per ring; a full
 * ring drops the packet, as a full socket buffer would.
 */
final class RadsecLink {

    /** Requests: route (8), NAS index (4), packet. Replies: route (8), packet. */
    static final int PACKET_MSG = 1;
    /** The route of a packet that came over UDP: answered from the socket. */
    static final long UDP = -1;

    private static final int RING_CAPACITY = 1 << 20;

    /** The NAS entries allowed over RadSec, with their RadSec secret; a request carries its index. */
    final NasClient[] clients;

    final RingBuffer toAuth = ring();
    final RingBuffer fromAuth = ring();
    final RingBuffer toAccounting = ring();
    final RingBuffer fromAccounting = ring();
    /** CoA and Disconnect-Requests for a NAS's connection: NAS index (4), packet (ADR 0036). */
    final RingBuffer toNas = ring();
    /** Their ACKs and NAKs: NAS index (4), packet. */
    final RingBuffer fromNas = ring();

    RadsecLink(NasClient[] clients) {
        this.clients = clients;
    }

    static long route(int connection, int generation) {
        return ((long) generation << 32) | connection;
    }

    static int connection(long route) {
        return (int) route;
    }

    static int generation(long route) {
        return (int) (route >>> 32);
    }

    /** A request for an agent; {@code false} when its ring is full. */
    static boolean request(RingBuffer ring, long route, int nas, DirectBuffer packet, int offset, int length) {
        int index = ring.tryClaim(PACKET_MSG, 12 + length);
        if (index <= 0) {
            return false;
        }
        MutableDirectBuffer b = ring.buffer();
        b.putLong(index, route);
        b.putInt(index + 8, nas);
        b.putBytes(index + 12, packet, offset, length);
        ring.commit(index);
        return true;
    }

    /** A reply for the RadSec agent; {@code false} when its ring is full. */
    static boolean reply(RingBuffer ring, long route, DirectBuffer packet, int offset, int length) {
        int index = ring.tryClaim(PACKET_MSG, 8 + length);
        if (index <= 0) {
            return false;
        }
        MutableDirectBuffer b = ring.buffer();
        b.putLong(index, route);
        b.putBytes(index + 8, packet, offset, length);
        ring.commit(index);
        return true;
    }

    private static RingBuffer ring() {
        return new OneToOneRingBuffer(new UnsafeBuffer(
                BufferUtil.allocateDirectAligned(RING_CAPACITY + RingBufferDescriptor.TRAILER_LENGTH, 64)));
    }
}
