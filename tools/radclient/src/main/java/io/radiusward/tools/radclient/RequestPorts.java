/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.IntFunction;
import java.util.function.IntPredicate;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The UDP side of a load generator, as a NAS does it: requests over several ports (256 identifiers each), answers
 * matched by port and identifier and checked with the secret, the identical datagram sent again on a timeout and
 * given up after the retries. The generators decide what to send and what an answer counts as.
 */
final class RequestPorts<R extends RequestPorts.Outstanding> implements AutoCloseable {

    /**
     * How far sending may fall behind the rate and still catch up. A stall of the process (GC, a busy host) of up to
     * this long is made good by sending faster for a moment, so the delivered rate is the requested one; only a longer
     * stall drops its share instead of bursting it all at once.
     */
    static final long CATCH_UP_NANOS = 100_000_000L;

    /** Timeouts are seconds long: scanning every request in flight on each turn would only burn CPU. */
    private static final long TIMEOUT_SCAN_NANOS = 10_000_000L;

    /** A request sent and not answered yet. */
    static class Outstanding {
        byte[] bytes;
        int identifier;
        /** Index of the server it goes to. */
        int server;

        int attempts;
        long firstSentNanos;
        long deadlineNanos;
    }

    /** The datagram of a request with this identifier. */
    interface Encoder<R> {
        byte[] encode(R request, int identifier);
    }

    interface Answered<R> {
        void answered(R request, RadiusPacket answer, long latencyMicros) throws IOException;
    }

    interface GaveUp<R> {
        void gaveUp(R request) throws IOException;
    }

    private final Selector selector;
    private final List<RequestPort<R>> ports = new ArrayList<>();
    private final List<InetSocketAddress> servers;
    private final byte[] secret;
    private final long timeoutNanos;
    private final int retries;
    private final boolean retryOtherServer;
    private final IntPredicate answerCode;
    private final Random random;
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final RadiusPacket answer = new RadiusPacket();
    private final ByteBuffer receive = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private int inFlight;
    private long nextTimeoutScan;
    private long retransmissions;
    private long unmatched;
    private long sendStalls;
    private long sendDropped;

    /**
     * @param retryOtherServer a retransmission goes to the next server
     * @param answerCode the codes that answer these requests
     */
    RequestPorts(
            int count,
            List<InetSocketAddress> servers,
            byte[] secret,
            Duration timeout,
            int retries,
            boolean retryOtherServer,
            IntPredicate answerCode,
            Random random,
            IntFunction<R[]> array)
            throws IOException {
        this.servers = servers;
        this.secret = secret;
        this.timeoutNanos = timeout.toNanos();
        this.retries = retries;
        this.retryOtherServer = retryOtherServer;
        this.answerCode = answerCode;
        this.random = random;
        this.selector = Selector.open();
        try {
            for (int i = 0; i < count; i++) {
                ports.add(new RequestPort<>(selector, RequestPort.localAddress(servers), array));
            }
        } catch (IOException | RuntimeException e) {
            close();
            throw e;
        }
    }

    /** Ports for {@code rate} requests a second: identifiers for what may be in flight during a timeout. */
    static int portsFor(int rate, Duration timeout, int minimum) {
        return Math.max(minimum, rate * (int) Math.max(1, timeout.toSeconds()) / 200 + 1);
    }

    /** Whether a request can be sent now: a port has an identifier free. */
    boolean hasFree() {
        for (RequestPort<R> p : ports) {
            if (!p.freeIds.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    int inFlight() {
        return inFlight;
    }

    /** Sends {@code r} to its server from a port with a free identifier ({@link #hasFree} first). */
    void send(R r, long now, Encoder<R> encoder) throws IOException {
        RequestPort<R> port = null;
        int base = random.nextInt(ports.size());
        for (int i = 0; i < ports.size() && port == null; i++) {
            RequestPort<R> candidate = ports.get((base + i) % ports.size());
            if (!candidate.freeIds.isEmpty()) {
                port = candidate;
            }
        }
        if (port == null) {
            throw new IllegalStateException("no identifier free: ask hasFree() first");
        }
        int id = port.freeIds.poll();
        r.identifier = id;
        r.bytes = encoder.encode(r, id);
        port.inFlight[id] = r;
        r.firstSentNanos = now;
        r.attempts = 1;
        r.deadlineNanos = now + timeoutNanos;
        transmit(port, r.bytes, servers.get(r.server));
        inFlight++;
    }

    /** Waits up to a millisecond for answers; each authentic one is handed over with its latency. */
    void receive(Answered<R> answered) throws IOException {
        selector.select(1);
        for (SelectionKey key : selector.selectedKeys()) {
            RequestPort<R> port = RequestPort.<R>of(key);
            while (true) {
                receive.clear();
                if (port.channel.receive(receive) == null) {
                    break;
                }
                R r = match(port, receive.position());
                if (r != null) {
                    inFlight--;
                    answered.answered(r, answer, (System.nanoTime() - r.firstSentNanos) / 1000);
                }
            }
        }
        selector.selectedKeys().clear();
    }

    private R match(RequestPort<R> port, int length) {
        if (answer.wrap(new UnsafeBuffer(receive.array(), 0, length), 0, length) != DecodeStatus.OK
                || !answerCode.test(answer.code())) {
            unmatched++;
            return null;
        }
        int id = answer.identifier();
        R r = port.inFlight[id];
        if (r == null || !authenticator.verifyResponse(answer, new UnsafeBuffer(r.bytes), 4, secret)) {
            unmatched++;
            return null;
        }
        port.inFlight[id] = null;
        port.freeIds.add(id);
        return r;
    }

    /**
     * Requests past their deadline: sent again, the identical datagram from the same port like a NAS, until the
     * retries are used up; then given up.
     */
    void expire(long now, GaveUp<R> gaveUp) throws IOException {
        if (now < nextTimeoutScan) {
            return;
        }
        nextTimeoutScan = now + TIMEOUT_SCAN_NANOS;
        for (RequestPort<R> port : ports) {
            for (int id = 0; id < RequestPort.IDS; id++) {
                R r = port.inFlight[id];
                if (r == null || now <= r.deadlineNanos) {
                    continue;
                }
                if (r.attempts <= retries) {
                    if (retryOtherServer) {
                        r.server = (r.server + 1) % servers.size();
                    }
                    r.attempts++;
                    r.deadlineNanos = now + timeoutNanos;
                    transmit(port, r.bytes, servers.get(r.server));
                    retransmissions++;
                } else {
                    port.inFlight[id] = null;
                    port.freeIds.add(id);
                    inFlight--;
                    gaveUp.gaveUp(r);
                }
            }
        }
    }

    /**
     * A non-blocking send returns 0 when the socket buffer is momentarily full and the datagram is then not sent
     * at all; retry briefly instead of losing it, and count what still could not be sent.
     */
    private void transmit(RequestPort<R> port, byte[] bytes, InetSocketAddress server) throws IOException {
        ByteBuffer datagram = ByteBuffer.wrap(bytes);
        for (int attempt = 0; attempt < 1000; attempt++) {
            if (port.channel.send(datagram, server) > 0) {
                return;
            }
            sendStalls++;
            java.util.concurrent.locks.LockSupport.parkNanos(50_000);
        }
        sendDropped++;
    }

    long retransmissions() {
        return retransmissions;
    }

    /** Answers that matched no request in flight (late, duplicate or not authentic). */
    long unmatched() {
        return unmatched;
    }

    /** Sends that found the socket buffer full. */
    long sendStalls() {
        return sendStalls;
    }

    /** Datagrams that could not be sent at all. */
    long sendDropped() {
        return sendDropped;
    }

    @Override
    public void close() throws IOException {
        for (RequestPort<R> port : ports) {
            port.channel.close();
        }
        selector.close();
    }
}
