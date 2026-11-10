/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicLongArray;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.Agent;
import org.agrona.concurrent.ManyToOneConcurrentArrayQueue;
import org.agrona.concurrent.MessageHandler;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends Disconnect-Requests and CoA-Requests to NAS (RFC 5176, ADR 0036) and waits for their ACK or NAK: over UDP to
 * the NAS's dynamic-authorization port, or over the NAS's RadSec connection. One thread; callers on any thread get a
 * future. A request is signed like an Accounting-Request and carries a Message-Authenticator; a response counts only
 * if its Response Authenticator (and Message-Authenticator, if present) verifies. Without an answer the request is
 * sent again ({@code coa.retries}, every {@code coa.timeout}), then given up.
 */
public final class DynamicAuthorization implements Agent {

    private static final Logger LOG = LogManager.getLogger(DynamicAuthorization.class);

    public static final int DISCONNECT_REQUEST = 40;
    public static final int DISCONNECT_ACK = 41;
    public static final int DISCONNECT_NAK = 42;
    public static final int COA_REQUEST = 43;
    public static final int COA_ACK = 44;
    public static final int COA_NAK = 45;
    static final int ERROR_CAUSE = 101;
    private static final int MESSAGE_AUTHENTICATOR = 80;

    /** What became of a request. */
    public enum Outcome {
        ACK,
        NAK,
        TIMEOUT,
        /** No address to send to, or 256 requests to that NAS already in flight. */
        UNREACHABLE
    }

    /** @param errorCause the NAK's Error-Cause (RFC 5176 §3.6), 0 if none */
    public record Result(Outcome outcome, int errorCause) {}

    private static final class Request {
        final int code;
        final byte[] attributes;
        final InetSocketAddress to; // null over RadSec
        final int radsecNas; // -1 over UDP
        final byte[] secret;
        final CompletableFuture<Result> result = new CompletableFuture<>();
        final UnsafeBuffer packet = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        int length;
        int identifier;
        int sent;
        long deadline;

        Request(int code, byte[] attributes, InetSocketAddress to, int radsecNas, byte[] secret) {
            this.code = code;
            this.attributes = attributes;
            this.to = to;
            this.radsecNas = radsecNas;
            this.secret = secret;
        }

        boolean sameDestination(Request other) {
            return radsecNas == other.radsecNas && (to == null ? other.to == null : to.equals(other.to));
        }
    }

    enum Counter {
        SENT,
        RESENT,
        ACK,
        NAK,
        TIMEOUT,
        UNREACHABLE,
        INVALID_RESPONSES
    }

    private final CoaConfig config;
    private final String host;
    private final RadsecLink radsec;
    private final ManyToOneConcurrentArrayQueue<Request> queue = new ManyToOneConcurrentArrayQueue<>(1024);
    private final List<Request> pending = new ArrayList<>();
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final RadiusPacket response = new RadiusPacket();
    private final ByteBuffer receive = ByteBuffer.allocateDirect(RadiusPacket.MAX_LENGTH);
    private final UnsafeBuffer received = new UnsafeBuffer(receive);
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    private final MessageHandler radsecHandler = this::onRadsec;
    private DatagramChannel channel;
    private int nextIdentifier;

    /**
     * @param host the local address to send from ({@code gateway.listen.host})
     * @param radsec the link to the RadSec agent, {@code null} without RadSec
     */
    DynamicAuthorization(CoaConfig config, String host, RadsecLink radsec) {
        this.config = config;
        this.host = host;
        this.radsec = radsec;
    }

    /** Sends a request over UDP; {@code attributes} are the RADIUS attributes, Message-Authenticator is added. */
    public CompletableFuture<Result> send(int code, byte[] attributes, InetSocketAddress to, byte[] secret) {
        return enqueue(new Request(code, attributes, to, -1, secret));
    }

    /** Sends a request over the RadSec connection of {@code radsecNas} (an index of {@link RadsecLink#clients}). */
    public CompletableFuture<Result> sendRadsec(int code, byte[] attributes, int radsecNas, byte[] secret) {
        return enqueue(new Request(code, attributes, null, radsecNas, secret));
    }

    private CompletableFuture<Result> enqueue(Request r) {
        if (!queue.offer(r)) {
            r.result.complete(new Result(Outcome.UNREACHABLE, 0));
        }
        return r.result;
    }

    @Override
    public void onStart() {
        try {
            channel = DatagramChannel.open();
            channel.bind(new InetSocketAddress(host, 0));
            channel.configureBlocking(false);
        } catch (IOException e) {
            throw new IllegalStateException("cannot open the CoA socket on " + host, e);
        }
    }

    @Override
    public int doWork() throws IOException {
        long now = System.nanoTime();
        int work = 0;
        for (Request r = queue.poll(); r != null; r = queue.poll()) {
            start(r, now);
            work++;
        }
        for (int i = 0; i < 64; i++) {
            receive.clear();
            SocketAddress from = channel.receive(receive);
            if (from == null) {
                break;
            }
            onResponse(received, 0, receive.position(), (InetSocketAddress) from, -1);
            work++;
        }
        if (radsec != null) {
            work += radsec.fromNas.read(radsecHandler, 64);
        }
        if (!pending.isEmpty()) {
            work += timeouts(now);
        }
        return work;
    }

    private void start(Request r, long now) {
        int id = identifierFor(r);
        if (id < 0) {
            complete(r, Outcome.UNREACHABLE, 0);
            return;
        }
        r.identifier = id;
        int length = RadiusPacket.HEADER_LENGTH + r.attributes.length + 18;
        if (length > RadiusPacket.MAX_LENGTH) {
            complete(r, Outcome.UNREACHABLE, 0);
            return;
        }
        UnsafeBuffer p = r.packet;
        p.putByte(0, (byte) r.code);
        p.putByte(1, (byte) id);
        p.putShort(2, (short) length, java.nio.ByteOrder.BIG_ENDIAN);
        p.putBytes(RadiusPacket.HEADER_LENGTH, r.attributes);
        int ma = RadiusPacket.HEADER_LENGTH + r.attributes.length;
        p.putByte(ma, (byte) MESSAGE_AUTHENTICATOR);
        p.putByte(ma + 1, (byte) 18);
        p.setMemory(ma + 2, 16, (byte) 0);
        authenticator.signAccountingRequest(p, 0, length, ma, r.secret);
        r.length = length;
        pending.add(r);
        transmit(r, now);
        increment(Counter.SENT);
    }

    /** An identifier no request to the same destination is waiting with; -1 if all 256 are. */
    private int identifierFor(Request r) {
        for (int n = 0; n < 256; n++) {
            int id = (nextIdentifier + n) & 0xFF;
            boolean taken = false;
            for (Request p : pending) {
                if (p.identifier == id && p.sameDestination(r)) {
                    taken = true;
                    break;
                }
            }
            if (!taken) {
                nextIdentifier = (id + 1) & 0xFF;
                return id;
            }
        }
        return -1;
    }

    private void transmit(Request r, long now) {
        r.sent++;
        r.deadline = now + config.timeout().toNanos();
        try {
            if (r.to != null) {
                channel.send(ByteBuffer.wrap(r.packet.byteArray(), 0, r.length), r.to);
            } else if (radsec != null) {
                int index = radsec.toNas.tryClaim(RadsecLink.PACKET_MSG, 4 + r.length);
                if (index > 0) {
                    radsec.toNas.buffer().putInt(index, r.radsecNas);
                    radsec.toNas.buffer().putBytes(index + 4, r.packet, 0, r.length);
                    radsec.toNas.commit(index);
                }
            }
        } catch (IOException e) {
            LOG.debug("CoA send to {} failed: {}", r.to, e.toString()); // the next try or the timeout decides
        }
    }

    private int timeouts(long now) {
        int work = 0;
        for (Iterator<Request> it = pending.iterator(); it.hasNext(); ) {
            Request r = it.next();
            if (now - r.deadline < 0) {
                continue;
            }
            work++;
            if (r.sent <= config.retries()) {
                transmit(r, now);
                increment(Counter.RESENT);
            } else {
                it.remove();
                complete(r, Outcome.TIMEOUT, 0);
            }
        }
        return work;
    }

    private void onRadsec(int msgTypeId, DirectBuffer buffer, int index, int length) {
        int nas = buffer.getInt(index);
        received.putBytes(0, buffer, index + 4, length - 4);
        onResponse(received, 0, length - 4, null, nas);
    }

    private void onResponse(DirectBuffer buffer, int offset, int length, InetSocketAddress from, int radsecNas) {
        if (response.wrap(buffer, offset, length) != DecodeStatus.OK) {
            increment(Counter.INVALID_RESPONSES);
            return;
        }
        int code = response.code();
        for (Iterator<Request> it = pending.iterator(); it.hasNext(); ) {
            Request r = it.next();
            boolean destination = from != null
                    ? r.to != null && r.to.getAddress().equals(from.getAddress())
                    : r.radsecNas == radsecNas;
            if (!destination || r.identifier != response.identifier()) {
                continue;
            }
            if ((code != r.code + 1 && code != r.code + 2)
                    || !authenticator.verifyResponse(response, r.packet, RadiusPacket.AUTHENTICATOR_OFFSET, r.secret)
                    || (response.hasMessageAuthenticator()
                            && !authenticator.verifyResponseMessageAuthenticator(
                                    response, r.packet, RadiusPacket.AUTHENTICATOR_OFFSET, r.secret))) {
                increment(Counter.INVALID_RESPONSES);
                return;
            }
            it.remove();
            complete(r, code == r.code + 1 ? Outcome.ACK : Outcome.NAK, errorCause());
            return;
        }
        increment(Counter.INVALID_RESPONSES); // late, or for no request of ours
    }

    private int errorCause() {
        int at = response.findAttribute(ERROR_CAUSE);
        if (at < 0 || (response.buffer().getByte(at + 1) & 0xFF) != 6) {
            return 0;
        }
        return response.buffer().getInt(at + 2, java.nio.ByteOrder.BIG_ENDIAN);
    }

    private void complete(Request r, Outcome outcome, int errorCause) {
        increment(
                switch (outcome) {
                    case ACK -> Counter.ACK;
                    case NAK -> Counter.NAK;
                    case TIMEOUT -> Counter.TIMEOUT;
                    case UNREACHABLE -> Counter.UNREACHABLE;
                });
        r.result.complete(new Result(outcome, errorCause));
    }

    private void increment(Counter c) {
        counts.incrementAndGet(c.ordinal());
    }

    long get(Counter c) {
        return counts.get(c.ordinal());
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter(
                "radiusward_gateway_coa_requests_total",
                "CoA and Disconnect-Requests to NAS (RFC 5176): sent, resent and what came of them");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
        }
    }

    @Override
    public void onClose() {
        for (Request r : pending) {
            r.result.complete(new Result(Outcome.TIMEOUT, 0));
        }
        pending.clear();
        for (Request r = queue.poll(); r != null; r = queue.poll()) {
            r.result.complete(new Result(Outcome.UNREACHABLE, 0));
        }
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            LOG.debug("closing the CoA socket: {}", e.toString());
        }
    }

    @Override
    public String roleName() {
        return "dynamic-authorization";
    }
}
