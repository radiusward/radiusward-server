/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * A RADIUS client over UDP for development and tests, behaving as a NAS: it sends a request, sends the identical
 * datagram again when no answer comes in time, and accepts only an answer with the request's identifier whose Response
 * Authenticator (and Message-Authenticator, if present) verifies with the shared secret; anything else is ignored,
 * as a NAS ignores it.
 *
 * <pre>{@code
 * try (RadiusClient client = RadiusClient.udp("127.0.0.1", 1812, "testing123")) {
 *     Response r = client.pap("alice", "secret").orElseThrow();
 *     assert r.isAccept();
 * }
 * }</pre>
 *
 * <p>One socket for the client's lifetime, so every request comes from the same address and port. Not thread-safe:
 * one client per thread.
 */
public final class RadiusClient implements AutoCloseable {

    private final InetSocketAddress server;
    private final byte[] secret;
    private final DatagramChannel channel;
    private final Selector selector;
    private final ByteBuffer receive = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final AtomicInteger identifier = new AtomicInteger();
    private Duration timeout = Duration.ofSeconds(3);
    private int retries = 2;

    private RadiusClient(InetSocketAddress server, byte[] secret) {
        this.server = server;
        this.secret = secret.clone();
        try {
            this.channel = DatagramChannel.open();
            channel.configureBlocking(false);
            channel.connect(server);
            this.selector = Selector.open();
            channel.register(selector, SelectionKey.OP_READ);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot open a UDP socket to " + server, e);
        }
    }

    /** A client of the RADIUS server at {@code server} with this shared secret. */
    public static RadiusClient udp(InetSocketAddress server, byte[] secret) {
        return new RadiusClient(server, secret);
    }

    public static RadiusClient udp(String host, int port, String secret) {
        return udp(new InetSocketAddress(host, port), secret.getBytes(StandardCharsets.UTF_8));
    }

    /** How long to wait for an answer before sending again (default 3 s). */
    public RadiusClient timeout(Duration timeout) {
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        this.timeout = timeout;
        return this;
    }

    /** How many times to send again after the first attempt (default 2, so 3 attempts). */
    public RadiusClient retries(int retries) {
        if (retries < 0) {
            throw new IllegalArgumentException("retries must not be negative");
        }
        this.retries = retries;
        return this;
    }

    public InetSocketAddress server() {
        return server;
    }

    /** The next identifier, 0 to 255 and around again. */
    public int nextIdentifier() {
        return identifier.getAndIncrement() & 0xFF;
    }

    /** An Access-Request with the next identifier and the client's secret, to fill and {@link #send(PacketBuilder)}. */
    public PacketBuilder accessRequest() {
        return PacketBuilder.accessRequest(nextIdentifier()).secret(secret);
    }

    /** An Accounting-Request with the next identifier and the client's secret. */
    public PacketBuilder accountingRequest() {
        return PacketBuilder.accountingRequest(nextIdentifier()).secret(secret);
    }

    /** A PAP login with Message-Authenticator (RADIUS servers require it by default). */
    public Optional<Response> pap(String user, String password) {
        return send(accessRequest().messageAuthenticator().attribute(1, user).password(password));
    }

    /** A CHAP login with Message-Authenticator. */
    public Optional<Response> chap(String user, String password) {
        return send(accessRequest().messageAuthenticator().attribute(1, user).chap(password));
    }

    /** An MS-CHAPv2 login with Message-Authenticator. */
    public Optional<Response> msChapV2(String user, String password) {
        return send(accessRequest().messageAuthenticator().attribute(1, user).msChapV2(user, password));
    }

    /** Status-Server (RFC 5997): whether the server is there, without a login. */
    public Optional<Response> statusServer() {
        return send(PacketBuilder.statusServer(nextIdentifier())
                .messageAuthenticator()
                .secret(secret));
    }

    /** Builds {@code request} (with the client's secret unless it has its own) and {@link #send(byte[]) sends} it. */
    public Optional<Response> send(PacketBuilder request) {
        if (!request.hasSecret()) {
            request.secret(secret);
        }
        return send(request.build());
    }

    /**
     * Sends {@code request} and waits for its verified answer, sending it again after each {@link #timeout} up to
     * {@link #retries} times; empty if none came.
     */
    public Optional<Response> send(byte[] request) {
        long start = System.nanoTime();
        UnsafeBuffer requestBuffer = new UnsafeBuffer(request);
        RadiusPacket answer = new RadiusPacket();
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        try {
            for (int attempt = 1; attempt <= retries + 1; attempt++) {
                channel.write(ByteBuffer.wrap(request));
                long deadline = System.nanoTime() + timeout.toNanos();
                long remaining;
                while ((remaining = deadline - System.nanoTime()) > 0) {
                    if (selector.select(Math.max(1, remaining / 1_000_000)) == 0) {
                        continue;
                    }
                    selector.selectedKeys().clear();
                    byte[] bytes = read();
                    if (bytes == null || (bytes[1] & 0xFF) != (request[1] & 0xFF)) {
                        continue; // nothing, or a late answer to an earlier request
                    }
                    if (answer.wrap(new UnsafeBuffer(bytes), 0, bytes.length) == DecodeStatus.OK
                            && authenticator.verifyResponse(answer, requestBuffer, 4, secret, false)) {
                        return Optional.of(new Response(bytes, attempt, Duration.ofNanos(System.nanoTime() - start)));
                    }
                }
            }
            return Optional.empty();
        } catch (IOException e) {
            throw new UncheckedIOException("sending to " + server, e);
        }
    }

    private byte[] read() throws IOException {
        receive.clear();
        try {
            if (channel.read(receive) < RadiusPacket.HEADER_LENGTH) {
                return null;
            }
        } catch (PortUnreachableException e) {
            return null; // nobody listens yet: wait for the timeout and send again
        }
        return Arrays.copyOf(receive.array(), receive.position());
    }

    @Override
    public void close() {
        try {
            selector.close();
            channel.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
