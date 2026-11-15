/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * A NAS for tests: one UDP socket on loopback, so a retransmission comes from the same source port and the gateways'
 * response caches see what they would see from a real NAS. Build its requests with {@link AccountingRequest}.
 */
public final class FakeNas implements AutoCloseable {

    /** The shared secret of {@link LocalCluster}'s NAS entry. */
    public static final byte[] SECRET = LocalCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    private final byte[] sharedSecret;
    private final DatagramChannel channel;

    public FakeNas() {
        this(SECRET);
    }

    /** With another shared secret, to verify the responses with. */
    public FakeNas(byte[] secret) {
        this.sharedSecret = secret.clone();
        try {
            channel = DatagramChannel.open();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        try {
            channel.bind(new InetSocketAddress("127.0.0.1", 0));
            channel.configureBlocking(false);
        } catch (IOException e) {
            close();
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Sends {@code request} to a gateway on loopback, retransmitting like a NAS, and returns the verified
     * Accounting-Response; {@code null} if none arrives within the attempts. A response to this request with a wrong
     * authenticator or another code fails at once.
     */
    public byte[] exchange(int port, byte[] request, int attempts, Duration timeout) {
        byte[] response = reply(port, request, attempts, timeout);
        if (response == null) {
            return null;
        }
        RadiusPacket view = new RadiusPacket();
        view.wrap(new UnsafeBuffer(response), 0, response.length);
        if (!new RadiusAuthenticator().verifyResponse(view, new UnsafeBuffer(request), 4, sharedSecret)) {
            throw new AssertionError("Response Authenticator of the answer to request " + (request[1] & 0xFF));
        }
        if (view.code() != RadiusCode.ACCOUNTING_RESPONSE) {
            throw new AssertionError("expected an Accounting-Response, got code " + view.code());
        }
        return response;
    }

    /** {@link #exchange} with a NAS's patience (8 attempts, 2 s each); fails if no Accounting-Response comes. */
    public byte[] ack(int port, byte[] request) {
        byte[] response = exchange(port, request, 8, Duration.ofSeconds(2));
        if (response == null) {
            throw new AssertionError("no Accounting-Response to request " + (request[1] & 0xFF));
        }
        return response;
    }

    /** Any reply with the request's identifier, unverified (8 attempts, 3 s each); fails if none comes. */
    public byte[] reply(int port, byte[] request) {
        byte[] response = reply(port, request, 8, Duration.ofSeconds(3));
        if (response == null) {
            throw new AssertionError("no reply to request " + (request[1] & 0xFF));
        }
        return response;
    }

    private byte[] reply(int port, byte[] request, int attempts, Duration timeout) {
        try {
            DatagramChannel c = channel;
            InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);
            ByteBuffer in = ByteBuffer.allocate(4096);
            for (int attempt = 0; attempt < attempts; attempt++) {
                c.send(ByteBuffer.wrap(request), target);
                long deadline = System.nanoTime() + timeout.toNanos();
                while (System.nanoTime() < deadline) {
                    in.clear();
                    if (c.receive(in) != null && in.position() >= 2 && in.get(1) == request[1]) {
                        return Arrays.copyOf(in.array(), in.position()); // else a late answer to an earlier request
                    }
                    Thread.sleep(2);
                }
            }
            return null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    @Override
    public void close() {
        try {
            channel.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
