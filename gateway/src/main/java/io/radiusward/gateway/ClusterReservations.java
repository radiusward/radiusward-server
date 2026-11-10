/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.protocol.AuthReservationEncoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.locks.LockSupport;
import org.agrona.BufferUtil;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.ManyToOneRingBuffer;
import org.agrona.concurrent.ringbuffer.RingBuffer;
import org.agrona.concurrent.ringbuffer.RingBufferDescriptor;

/**
 * Simultaneous-use reservations from the access workers to the cluster (ADR 0023). Workers write {@code
 * AuthReservation} commands into a many-to-one ring that the {@link ClusterClientAgent} forwards to the cluster; the
 * cluster's answer, sent after the commit, comes back through a mailbox per worker. A worker waits for its answer up to
 * {@code gateway.auth.reservation.timeout}; without one the request is not answered and the NAS retransmits, which
 * asks again — a second reservation for the same device only extends the first.
 */
final class ClusterReservations {

    static final int REQUEST_MSG = 1;
    private static final int RING_CAPACITY = 64 * 1024;
    private static final long TAG = 1L << 62; // apart from the accounting path's correlation ids
    private static final int WORKER_SHIFT = 40;
    private static final long SEQUENCE_MASK = (1L << WORKER_SHIFT) - 1;

    private final ManyToOneRingBuffer requests = new ManyToOneRingBuffer(new UnsafeBuffer(
            BufferUtil.allocateDirectAligned(RING_CAPACITY + RingBufferDescriptor.TRAILER_LENGTH, 64)));
    private final AtomicLongArray answered;
    private final AtomicIntegerArray results;
    private final AtomicLongArray sqns; // the SQN of an SqnResult, beside its outcome in results
    private final int gatewayId;
    private final long timeoutNs;
    private final int ttlSeconds;

    ClusterReservations(int workers, int gatewayId, Duration timeout, Duration ttl) {
        this.answered = new AtomicLongArray(workers);
        this.results = new AtomicIntegerArray(workers);
        this.sqns = new AtomicLongArray(workers);
        this.gatewayId = gatewayId;
        this.timeoutNs = timeout.toNanos();
        this.ttlSeconds = (int) ttl.toSeconds();
    }

    /** Read by the cluster client agent. */
    RingBuffer requests() {
        return requests;
    }

    /** An {@code AuthReservationResult} from the cluster; called on the cluster client thread. */
    void deliver(long correlationId, int result) {
        if ((correlationId & TAG) == 0) {
            return;
        }
        int worker = (int) ((correlationId & ~TAG) >>> WORKER_SHIFT);
        if (worker < 0 || worker >= results.length()) {
            return;
        }
        results.set(worker, result);
        answered.set(worker, correlationId); // after the result: a worker that sees its id reads its result
    }

    /** An {@code SqnResult} from the cluster; called on the cluster client thread. */
    void deliverSqn(long correlationId, int outcome, long sqn) {
        if ((correlationId & TAG) == 0) {
            return;
        }
        int worker = (int) ((correlationId & ~TAG) >>> WORKER_SHIFT);
        if (worker < 0 || worker >= results.length()) {
            return;
        }
        sqns.set(worker, sqn);
        results.set(worker, outcome);
        answered.set(worker, correlationId); // last: a worker that sees its id reads the rest
    }

    /** The {@link SessionLimits} of worker {@code index}; used only on that worker's thread. */
    SessionLimits forWorker(int index) {
        return new Worker(index);
    }

    private final class Worker implements SessionLimits {
        private final int index;
        private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
        private final MessageHeaderEncoder header = new MessageHeaderEncoder();
        private final AuthReservationEncoder encoder = new AuthReservationEncoder();
        private final io.radiusward.protocol.SqnNextEncoder sqnEncoder = new io.radiusward.protocol.SqnNextEncoder();
        private long sequence;

        Worker(int index) {
            this.index = index;
        }

        @Override
        public long nextSqn(long subscriberKey, long floor) {
            long correlationId = TAG | ((long) index << WORKER_SHIFT) | (++sequence & SEQUENCE_MASK);
            sqnEncoder
                    .wrapAndApplyHeader(buffer, 0, header)
                    .correlationId(correlationId)
                    .gatewayId(gatewayId)
                    .subscriberKey(subscriberKey)
                    .floor(floor);
            if (!requests.write(
                    REQUEST_MSG, buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + sqnEncoder.encodedLength())) {
                return SQN_UNAVAILABLE;
            }
            if (!await(correlationId)) {
                return SQN_UNAVAILABLE;
            }
            return switch (results.get(index)) {
                case 0 -> sqns.get(index); // OK
                case 1 -> SQN_UNSUPPORTED;
                default -> SQN_UNAVAILABLE; // CAPACITY: no room for another subscriber
            };
        }

        /** Waits for the answer to {@code correlationId}; {@code false} after the timeout (a late one is ignored). */
        private boolean await(long correlationId) {
            long deadline = System.nanoTime() + timeoutNs;
            int spins = 0;
            while (answered.get(index) != correlationId) {
                if (System.nanoTime() - deadline > 0) {
                    return false;
                }
                if (++spins < 200) {
                    Thread.onSpinWait();
                } else {
                    LockSupport.parkNanos(20_000);
                }
            }
            return true;
        }

        @Override
        public int reserve(long userKey, long deviceKey, int maxDevices) {
            long correlationId = TAG | ((long) index << WORKER_SHIFT) | (++sequence & SEQUENCE_MASK);
            encoder.wrapAndApplyHeader(buffer, 0, header)
                    .correlationId(correlationId)
                    .gatewayId(gatewayId)
                    .userKey(userKey)
                    .deviceKey(deviceKey)
                    .maxDevices(Math.min(maxDevices, 0xFFFF))
                    .ttlSeconds(ttlSeconds);
            if (!requests.write(
                    REQUEST_MSG, buffer, 0, MessageHeaderEncoder.ENCODED_LENGTH + encoder.encodedLength())) {
                return UNAVAILABLE;
            }
            if (!await(correlationId)) {
                return UNAVAILABLE; // a late answer is ignored: the next request has another id
            }
            return switch (results.get(index)) {
                case GRANTED -> GRANTED;
                case DENIED -> DENIED;
                case UNSUPPORTED -> UNSUPPORTED;
                default -> UNAVAILABLE; // CAPACITY: the cluster has no room for the place
            };
        }
    }
}
