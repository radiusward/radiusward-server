/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * A blocking RADIUS over DTLS 1.2 client for tests (RFC 7360) on the JDK's {@link SSLEngine}: one association, one
 * RADIUS packet per record. It can drop datagrams from the server and hold back its own retransmissions, to see the
 * server's retransmission timer at work.
 */
public final class DtlsClient implements AutoCloseable {

    private final DatagramSocket socket;
    private final SSLEngine engine;
    private final InetSocketAddress server;
    private final ByteBuffer empty = ByteBuffer.allocate(0);
    private int received;
    /** Datagrams from the server dropped by their number, counted from 1; {@code null}: none. */
    private final int[] drop;
    /** Whether a receive timeout during the handshake sends the last flight again. */
    private final boolean retransmits;

    public DtlsClient(int port, SSLContext context) throws Exception {
        this(port, context, new DatagramSocket(0, InetAddress.getLoopbackAddress()), null, true);
    }

    public DtlsClient(int port, SSLContext context, DatagramSocket socket, int[] drop, boolean retransmits)
            throws Exception {
        this.socket = socket;
        this.server = new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
        this.drop = drop;
        this.retransmits = retransmits;
        socket.setSoTimeout(1_000);
        engine = context.createSSLEngine("127.0.0.1", port);
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[] {"DTLSv1.2"});
        try {
            handshake();
        } catch (Exception e) {
            socket.close();
            throw e;
        }
    }

    /** The local port, for a client that comes back from the same address (a restarted NAS). */
    public int localPort() {
        return socket.getLocalPort();
    }

    private void handshake() throws Exception {
        engine.beginHandshake();
        long deadline = System.nanoTime() + 15_000_000_000L;
        while (true) {
            if (System.nanoTime() > deadline) {
                throw new SSLException("DTLS handshake timed out");
            }
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            switch (hs) {
                case NEED_WRAP -> wrapAndSend(empty);
                case NEED_TASK -> runTasks();
                case NEED_UNWRAP_AGAIN ->
                    engine.unwrap(empty, ByteBuffer.allocate(engine.getSession().getApplicationBufferSize()));
                case NEED_UNWRAP -> {
                    ByteBuffer datagram = receiveDatagram();
                    if (datagram == null) {
                        if (retransmits) {
                            wrapAndSend(empty); // the JDK sends its last flight again
                        }
                        continue;
                    }
                    ByteBuffer app = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
                    while (datagram.hasRemaining()) {
                        SSLEngineResult r = engine.unwrap(datagram, app);
                        if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                            throw new SSLException("closed by the server during the handshake");
                        }
                        if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            runTasks();
                        }
                        if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED
                                || r.bytesConsumed() == 0) {
                            break;
                        }
                    }
                }
                case NOT_HANDSHAKING, FINISHED -> {
                    return;
                }
            }
        }
    }

    private void runTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    private void wrapAndSend(ByteBuffer plain) throws IOException {
        do {
            ByteBuffer out = ByteBuffer.allocate(1 << 16);
            SSLEngineResult r = engine.wrap(plain, out);
            out.flip();
            if (out.hasRemaining()) {
                socket.send(new DatagramPacket(out.array(), out.limit(), server)); // close_notify comes with CLOSED
            }
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                if (plain.hasRemaining()) {
                    throw new SSLException("DTLS closed");
                }
                return;
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runTasks();
            }
        } while (plain.hasRemaining()
                || (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP && plain == empty));
    }

    /** The next datagram from the server not dropped on purpose; {@code null} after the socket timeout. */
    private ByteBuffer receiveDatagram() throws IOException {
        byte[] buffer = new byte[1 << 16];
        while (true) {
            DatagramPacket p = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(p);
            } catch (SocketTimeoutException e) {
                return null;
            }
            received++;
            if (drop != null && Arrays.stream(drop).anyMatch(n -> n == received)) {
                continue;
            }
            return ByteBuffer.wrap(Arrays.copyOf(buffer, p.getLength()));
        }
    }

    /** Sends one RADIUS packet in one record. */
    public void send(byte[] packet) throws IOException {
        wrapAndSend(ByteBuffer.wrap(packet));
    }

    /** Sends a datagram as it is, outside DTLS. */
    public void sendRaw(byte[] datagram) throws IOException {
        socket.send(new DatagramPacket(datagram, datagram.length, server));
    }

    /** The next RADIUS packet, or {@code null} when none arrives within {@code millis} or the server closed. */
    public byte[] receive(int millis) throws IOException {
        long deadline = System.nanoTime() + millis * 1_000_000L;
        socket.setSoTimeout(Math.max(1, millis));
        try {
            while (System.nanoTime() < deadline) {
                ByteBuffer datagram = receiveDatagram();
                if (datagram == null) {
                    return null;
                }
                ByteBuffer app = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
                while (datagram.hasRemaining()) {
                    SSLEngineResult r = engine.unwrap(datagram, app);
                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                        return null;
                    }
                    if (r.bytesProduced() > 0) {
                        app.flip();
                        byte[] packet = new byte[app.remaining()];
                        app.get(packet);
                        return packet;
                    }
                    if (r.bytesConsumed() == 0) {
                        break;
                    }
                }
            }
            return null;
        } finally {
            socket.setSoTimeout(1_000);
        }
    }

    public byte[] receive() throws IOException {
        return receive(5_000);
    }

    /** Leaves without close_notify, as a NAS that loses power does. */
    public void abandon() {
        socket.close();
    }

    @Override
    public void close() {
        try {
            engine.closeOutbound();
            wrapAndSend(empty);
        } catch (IOException | RuntimeException e) {
            // closing anyway
        }
        socket.close();
    }
}
