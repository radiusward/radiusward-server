/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicLongArray;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * One RadSec (RFC 6614) or plain TCP (RFC 6613) connection of the {@link RadsecAgent}: what was read, the TLS
 * handshake and record layer, the RADIUS packets found in the stream (each forwarded to the agent that decides it),
 * and what waits to be written. Used on the agent's thread only.
 */
final class StreamConnection {

    /** Output a peer may leave unread before the connection is dropped. */
    private static final int MAX_PENDING_OUTPUT = 1 << 20;

    /** The TLS handshake of a connection is done: the agent binds it to its NAS entry. */
    interface Handshakes {
        void established(StreamConnection c) throws IOException;
    }

    final int index;
    final int generation;
    final SocketChannel channel;
    final SSLEngine engine;
    final InetSocketAddress remote;
    final long openedAt;
    final long acceptedAt = System.currentTimeMillis(); // to compare with the TLS session's creation time
    /** Plain TCP (no engine): {@link RadsecAgent#AUTH_PORT} or {@link RadsecAgent#ACCOUNTING_PORT}; 0 for TLS. */
    final int port;
    /** The agent's counters this connection counts in: RadSec's, or plain TCP's. */
    final AtomicLongArray counters;

    SelectionKey key;
    long lastActivity;
    /** Index in {@link RadsecLink#clients} once the handshake is done and the NAS known; -1 before. */
    int nas = -1;

    private final RadsecPeers peers;
    private final Handshakes handshakes;
    private final ByteBuffer appIn;
    private final UnsafeBuffer appView;
    private final ByteBuffer empty = ByteBuffer.allocate(0);
    private ByteBuffer netIn;
    private ByteBuffer netOut;

    StreamConnection(
            int index,
            int generation,
            SocketChannel channel,
            SSLEngine engine,
            long now,
            int port,
            AtomicLongArray counters,
            RadsecPeers peers,
            Handshakes handshakes)
            throws IOException {
        this.index = index;
        this.generation = generation;
        this.channel = channel;
        this.engine = engine;
        this.port = port;
        this.counters = counters;
        this.peers = peers;
        this.handshakes = handshakes;
        this.remote = (InetSocketAddress) channel.getRemoteAddress();
        this.openedAt = now;
        this.lastActivity = now;
        int packetSize =
                engine == null ? RadiusPacket.MAX_LENGTH : engine.getSession().getPacketBufferSize();
        netIn = ByteBuffer.allocate(packetSize);
        appIn = ByteBuffer.allocate(
                (engine == null ? RadiusPacket.MAX_LENGTH : engine.getSession().getApplicationBufferSize())
                        + RadiusPacket.MAX_LENGTH);
        appView = new UnsafeBuffer(appIn);
        netOut = ByteBuffer.allocate(packetSize * 2);
    }

    long route() {
        return RadsecLink.route(index, generation);
    }

    /**
     * Reads what arrived and acts on it: handshake steps, then packets to the deciding agents; then writes what that
     * produced.
     *
     * @return {@code false} if the peer closed the connection
     * @throws IOException on a broken connection, a failed handshake or a malformed packet (RFC 6613 §2.6.4: close)
     */
    boolean read(long now) throws IOException {
        if (engine == null) {
            if (channel.read(appIn) < 0) {
                return false;
            }
            lastActivity = now;
            dispatch();
            flush();
            return true;
        }
        if (!netIn.hasRemaining()) {
            netIn = SslEngines.grow(netIn, engine.getSession().getPacketBufferSize());
        }
        if (channel.read(netIn) < 0) {
            return false;
        }
        lastActivity = now;
        netIn.flip();
        boolean open;
        try {
            open = progress();
        } finally {
            netIn.compact();
        }
        if (open) {
            flush();
        }
        return open;
    }

    /** Drives the engine over what was read; {@code false} if the peer closed TLS. */
    private boolean progress() throws IOException {
        while (channel.isOpen()) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                SslEngines.runTasks(engine); // certificate checks; OCSP may wait for its timeout (ADR 0033)
                continue;
            }
            if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                send(empty);
                continue;
            }
            if (!netIn.hasRemaining() && hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                return true;
            }
            SSLEngineResult r = engine.unwrap(netIn, appIn);
            switch (r.getStatus()) {
                case BUFFER_UNDERFLOW -> {
                    return true; // the rest of the record is still on its way
                }
                case BUFFER_OVERFLOW -> {
                    dispatch();
                    if (appIn.remaining() < engine.getSession().getApplicationBufferSize()) {
                        throw new SSLException("plaintext buffer full");
                    }
                }
                case CLOSED -> {
                    return false;
                }
                default -> {}
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                established();
            }
            dispatch();
        }
        return true;
    }

    private void established() throws IOException {
        if (nas < 0) {
            handshakes.established(this);
        }
    }

    /** Encrypts {@code plain} (or a handshake message) into the output; plain TCP copies it. Then {@link #flush}. */
    void send(ByteBuffer plain) throws IOException {
        if (engine == null) {
            if (netOut.remaining() < plain.remaining()) {
                if (netOut.capacity() + plain.remaining() > MAX_PENDING_OUTPUT) {
                    throw new IOException("peer does not read its replies");
                }
                netOut = SslEngines.grow(netOut, plain.remaining());
            }
            netOut.put(plain);
            return;
        }
        do {
            int need = engine.getSession().getPacketBufferSize();
            if (netOut.remaining() < need) {
                if (netOut.capacity() + need > MAX_PENDING_OUTPUT) {
                    throw new IOException("peer does not read its replies");
                }
                netOut = SslEngines.grow(netOut, need);
            }
            SSLEngineResult r = engine.wrap(plain, netOut);
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("TLS closed");
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                established();
            }
        } while (plain.hasRemaining());
    }

    /** Whole RADIUS packets from the plaintext, each to the agent that decides it. */
    private void dispatch() throws IOException {
        ByteBuffer in = appIn;
        in.flip();
        try {
            while (in.remaining() >= 4) { // code, identifier, length: enough to judge the length
                int at = in.position();
                int length = in.getShort(at + 2) & 0xFFFF;
                if (length < RadiusPacket.HEADER_LENGTH || length > RadiusPacket.MAX_LENGTH || nas < 0) {
                    counters.incrementAndGet(RadsecAgent.Counter.MALFORMED.ordinal());
                    throw new IOException("malformed RADIUS packet over TCP"); // RFC 6613 §2.6.4: close
                }
                if (in.remaining() < length) {
                    break;
                }
                int code = in.get(at) & 0xFF;
                if ((port == RadsecAgent.AUTH_PORT && code == RadiusCode.ACCOUNTING_REQUEST)
                        || (port == RadsecAgent.ACCOUNTING_PORT && code == RadiusCode.ACCESS_REQUEST)) {
                    counters.incrementAndGet(RadsecAgent.Counter.NOT_HANDLED.ordinal()); // the other port's kind
                } else {
                    peers.forward(
                            route(), nas, appView, code, at, length, counters, port == RadsecAgent.ACCOUNTING_PORT);
                }
                in.position(at + length);
            }
        } finally {
            in.compact();
        }
    }

    /** Writes what waits; asks to be told when the socket takes more, if some is left. */
    void flush() throws IOException {
        netOut.flip();
        try {
            channel.write(netOut);
        } finally {
            netOut.compact();
        }
        if (key.isValid()) {
            key.interestOps(
                    netOut.position() > 0 ? SelectionKey.OP_READ | SelectionKey.OP_WRITE : SelectionKey.OP_READ);
        }
    }

    /** Closes the connection: TLS's close_notify first, best effort, then the socket. */
    void shut() throws IOException {
        try {
            if (engine != null) {
                engine.closeOutbound();
                netOut.clear();
                engine.wrap(empty, netOut);
                netOut.flip();
                channel.write(netOut);
            }
        } catch (IOException | RuntimeException e) {
            // closing anyway
        }
        key.cancel();
        channel.close();
    }
}
