/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The NAS side of CoA and Disconnect (RFC 5176): a UDP port that receives CoA-Requests and Disconnect-Requests from a
 * RADIUS server, keeps those whose Request Authenticator verifies with the shared secret, and answers each as
 * {@link #answer} decides (ACK by default), signed as a NAS signs it.
 *
 * <pre>{@code
 * try (CoaListener nas = CoaListener.bind(0, "testing123")) {
 *     // nas.port() is the NAS entry's CoA port; then make the server send a Disconnect
 *     CoaRequest r = nas.await(1, Duration.ofSeconds(5)).getFirst();
 *     assert r.isDisconnect() && r.string(1).orElseThrow().equals("alice");
 * }
 * }</pre>
 */
public final class CoaListener implements AutoCloseable {

    /** How the NAS answers a request: ACK, or NAK with an Error-Cause (RFC 5176 §3.6), or not at all. */
    public sealed interface Answer {
        record Ack() implements Answer {}

        record Nak(int errorCause) implements Answer {}

        record Silence() implements Answer {}

        static Answer ack() {
            return new Ack();
        }

        /** E.g. 503 Session-Context-Not-Found, 404 Invalid-Request. */
        static Answer nak(int errorCause) {
            return new Nak(errorCause);
        }

        /** No answer: the server's retries and timeout are tested. */
        static Answer silence() {
            return new Silence();
        }
    }

    private final DatagramSocket socket;
    private final byte[] secret;
    private final List<CoaRequest> received = new ArrayList<>();
    private final AtomicInteger unverified = new AtomicInteger();
    private final Thread thread;
    private volatile Function<CoaRequest, Answer> answer = r -> Answer.ack();

    private CoaListener(DatagramSocket socket, byte[] secret) {
        this.socket = socket;
        this.secret = secret.clone();
        this.thread =
                Thread.ofVirtual().name("coa-listener-" + socket.getLocalPort()).start(this::serve);
    }

    /** Listens on loopback; {@code port} 0 picks a free one ({@link #port()}). */
    public static CoaListener bind(int port, byte[] secret) {
        return bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), secret);
    }

    public static CoaListener bind(int port, String secret) {
        return bind(port, secret.getBytes(StandardCharsets.UTF_8));
    }

    public static CoaListener bind(InetSocketAddress address, byte[] secret) {
        try {
            return new CoaListener(new DatagramSocket(address), secret);
        } catch (SocketException e) {
            throw new UncheckedIOException("cannot listen on " + address, e);
        }
    }

    /** How to answer from now on (default: ACK). */
    public CoaListener answer(Function<CoaRequest, Answer> answer) {
        this.answer = answer;
        return this;
    }

    public int port() {
        return socket.getLocalPort();
    }

    /** The verified requests so far, in order (a server's retransmission appears again). */
    public List<CoaRequest> received() {
        synchronized (received) {
            return List.copyOf(received);
        }
    }

    /** Forgets the requests received so far, e.g. between two steps of a test. */
    public void clear() {
        synchronized (received) {
            received.clear();
        }
    }

    /** Requests that did not verify with the secret, so were neither kept nor answered. */
    public int unverified() {
        return unverified.get();
    }

    /** Waits until {@code count} requests have arrived; fails after {@code timeout}. */
    public List<CoaRequest> await(int count, Duration timeout) throws InterruptedException {
        long deadline = System.nanoTime() + timeout.toNanos();
        synchronized (received) {
            while (received.size() < count) {
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    throw new AssertionError("expected " + count + " CoA/Disconnect requests, got " + received.size());
                }
                received.wait(Math.max(1, left / 1_000_000));
            }
            return List.copyOf(received);
        }
    }

    private void serve() {
        byte[] buffer = new byte[RadiusPacket.MAX_LENGTH];
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        while (!socket.isClosed()) {
            DatagramPacket in = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(in);
            } catch (IOException e) {
                return; // closed
            }
            byte[] bytes = Arrays.copyOf(in.getData(), in.getLength());
            RadiusPacket p = new RadiusPacket();
            if (p.wrap(new UnsafeBuffer(bytes), 0, bytes.length) != DecodeStatus.OK
                    || (p.code() != RadiusCode.COA_REQUEST && p.code() != RadiusCode.DISCONNECT_REQUEST)
                    || !authenticator.verifyAccountingRequest(p, secret)) {
                unverified.incrementAndGet();
                continue;
            }
            CoaRequest request = new CoaRequest(bytes, (InetSocketAddress) in.getSocketAddress());
            synchronized (received) {
                received.add(request);
                received.notifyAll();
            }
            byte[] reply = switch (answer.apply(request)) {
                case Answer.Ack a ->
                    PacketBuilder.reply(p.code() + 1, bytes).secret(secret).build();
                case Answer.Nak n ->
                    PacketBuilder.reply(p.code() + 2, bytes)
                            .uint32(101, n.errorCause())
                            .secret(secret)
                            .build();
                case Answer.Silence s -> null;
            };
            if (reply != null) {
                try {
                    socket.send(new DatagramPacket(reply, reply.length, in.getSocketAddress()));
                } catch (IOException e) {
                    return; // closed
                }
            }
        }
    }

    @Override
    public void close() {
        socket.close();
        try {
            thread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
