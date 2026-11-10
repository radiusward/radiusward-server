/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.SessionPageQueryEncoder;
import io.radiusward.protocol.SessionPageReportDecoder;
import io.radiusward.protocol.SessionQueryEncoder;
import io.radiusward.protocol.SessionReportDecoder;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.protocol.UserSessionsQueryEncoder;
import io.radiusward.protocol.UserSessionsReportDecoder;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import org.agrona.BufferUtil;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.ManyToOneRingBuffer;
import org.agrona.concurrent.ringbuffer.RingBuffer;
import org.agrona.concurrent.ringbuffer.RingBufferDescriptor;

/**
 * Questions from the gateway to the replicated state (ADR 0036): one session, a user's sessions, a page of sessions.
 * Any thread asks; the {@link ClusterClientAgent} sends the query and hands the report back. Operator and CoA work,
 * never per packet: replies are copied and decoded on the asking thread.
 */
public final class ClusterQueries {

    /** One session as the cluster knows it; {@code identity} holds its identifying RADIUS attributes. */
    public record Session(
            long keyHi,
            long keyLo,
            int nasId,
            long userKey,
            int firstSeen,
            int lastSeen,
            boolean active,
            byte[] identity) {

        /** An attribute of the identity as text, or {@code null}. */
        public String attribute(int type) {
            for (int at = 0; at + 2 <= identity.length; ) {
                int length = identity[at + 1] & 0xFF;
                if (length < 2 || at + length > identity.length) {
                    return null;
                }
                if ((identity[at] & 0xFF) == type) {
                    return new String(identity, at + 2, length - 2, java.nio.charset.StandardCharsets.UTF_8);
                }
                at += length;
            }
            return null;
        }
    }

    /** Sessions with a user from a store slot on; {@code nextSlot} -1 at the end. */
    public record Page(int nextSlot, List<Session> sessions) {}

    private final RingBuffer requests = new ManyToOneRingBuffer(
            new UnsafeBuffer(BufferUtil.allocateDirectAligned((1 << 16) + RingBufferDescriptor.TRAILER_LENGTH, 64)));
    private final ConcurrentHashMap<Long, CompletableFuture<byte[]>> waiting = new ConcurrentHashMap<>();
    /** Its own range, apart from accounting and reservation correlation ids (replies are told apart by type too). */
    private final AtomicLong correlation = new AtomicLong(1L << 62);

    RingBuffer requests() {
        return requests;
    }

    /** A report from the cluster; its correlation id is the first field after the header. */
    void deliver(DirectBuffer buffer, int offset, int length) {
        long id = buffer.getLong(offset + MessageHeaderEncoder.ENCODED_LENGTH);
        CompletableFuture<byte[]> f = waiting.remove(id);
        if (f != null) {
            byte[] copy = new byte[length];
            buffer.getBytes(offset, copy);
            f.complete(copy);
        }
    }

    /** The session with this key, or {@code null} if the cluster does not know it. */
    public Session session(long keyHi, long keyLo, Duration timeout) throws TimeoutException {
        long id = correlation.incrementAndGet();
        UnsafeBuffer b = new UnsafeBuffer(new byte[64]);
        new SessionQueryEncoder()
                .wrapAndApplyHeader(b, 0, new MessageHeaderEncoder())
                .correlationId(id)
                .sessionKeyHi(keyHi)
                .sessionKeyLo(keyLo);
        byte[] reply = ask(id, b, MessageHeaderEncoder.ENCODED_LENGTH + SessionQueryEncoder.BLOCK_LENGTH, timeout);
        SessionReportDecoder d =
                new SessionReportDecoder().wrapAndApplyHeader(new UnsafeBuffer(reply), 0, new MessageHeaderDecoder());
        if (d.status() == SessionStatus.UNKNOWN) {
            return null;
        }
        boolean active = d.status() == SessionStatus.ACTIVE;
        int nas = d.nasId();
        byte[] identity = new byte[d.identityLength()];
        d.getIdentity(identity, 0, identity.length);
        return new Session(keyHi, keyLo, nas, 0, 0, 0, active, identity);
    }

    /** The active sessions of a user ({@link UserKeys#user}), at most 64. */
    public List<Session> userSessions(long userKey, Duration timeout) throws TimeoutException {
        long id = correlation.incrementAndGet();
        UnsafeBuffer b = new UnsafeBuffer(new byte[64]);
        new UserSessionsQueryEncoder()
                .wrapAndApplyHeader(b, 0, new MessageHeaderEncoder())
                .correlationId(id)
                .userKey(userKey);
        byte[] reply = ask(id, b, MessageHeaderEncoder.ENCODED_LENGTH + UserSessionsQueryEncoder.BLOCK_LENGTH, timeout);
        UserSessionsReportDecoder d = new UserSessionsReportDecoder()
                .wrapAndApplyHeader(new UnsafeBuffer(reply), 0, new MessageHeaderDecoder());
        d.correlationId();
        List<Session> sessions = new ArrayList<>();
        for (UserSessionsReportDecoder.SessionsDecoder s : d.sessions()) {
            long hi = s.keyHi();
            long lo = s.keyLo();
            int nas = s.nasId();
            int first = s.firstSeen();
            int last = s.lastSeen();
            byte[] identity = new byte[s.identityLength()];
            s.getIdentity(identity, 0, identity.length);
            sessions.add(new Session(hi, lo, nas, userKey, first, last, true, identity));
        }
        return sessions;
    }

    /** Active sessions with a user from store slot {@code fromSlot} on, at most {@code max} (up to 64). */
    public Page page(int fromSlot, int max, Duration timeout) throws TimeoutException {
        long id = correlation.incrementAndGet();
        UnsafeBuffer b = new UnsafeBuffer(new byte[64]);
        new SessionPageQueryEncoder()
                .wrapAndApplyHeader(b, 0, new MessageHeaderEncoder())
                .correlationId(id)
                .fromSlot(fromSlot)
                .maxSessions(max);
        byte[] reply = ask(id, b, MessageHeaderEncoder.ENCODED_LENGTH + SessionPageQueryEncoder.BLOCK_LENGTH, timeout);
        SessionPageReportDecoder d = new SessionPageReportDecoder()
                .wrapAndApplyHeader(new UnsafeBuffer(reply), 0, new MessageHeaderDecoder());
        d.correlationId();
        int next = d.nextSlot();
        List<Session> sessions = new ArrayList<>();
        for (SessionPageReportDecoder.SessionsDecoder s : d.sessions()) {
            long hi = s.keyHi();
            long lo = s.keyLo();
            int nas = s.nasId();
            long user = s.userKey();
            byte[] identity = new byte[s.identityLength()];
            s.getIdentity(identity, 0, identity.length);
            sessions.add(new Session(hi, lo, nas, user, 0, 0, true, identity));
        }
        return new Page(next, sessions);
    }

    private byte[] ask(long id, UnsafeBuffer query, int length, Duration timeout) throws TimeoutException {
        CompletableFuture<byte[]> f = new CompletableFuture<>();
        waiting.put(id, f);
        try {
            if (!requests.write(1, query, 0, length)) {
                throw new TimeoutException("query ring full");
            }
            return f.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TimeoutException("interrupted");
        } catch (ExecutionException e) {
            throw new IllegalStateException(e.getCause());
        } finally {
            waiting.remove(id);
        }
    }
}
