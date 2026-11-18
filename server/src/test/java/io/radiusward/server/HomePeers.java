/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BooleanSupplier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

/**
 * Home server ends for tests of the proxy's connections ({@link HomeTcpClient}, {@link TlsClient},
 * {@link HomeDtlsClient}) driven directly: a selector loop as the proxy runs it, a DTLS home server on the JDK's
 * {@link SSLEngine} that can also stay silent, and server-side TLS contexts of a {@link TestPki}.
 */
final class HomePeers {

    private HomePeers() {}

    /** A server context for {@code protocol} ({@code TLS} or {@code DTLS}) with the PKI's server certificate. */
    static SSLContext serverContext(TestPki pki, String protocol) throws Exception {
        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, null);
        keys.setKeyEntry("server", pki.server.keys().getPrivate(), new char[0], new X509Certificate[] {
            pki.server.certificate(), pki.ca.certificate()
        });
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, new char[0]);
        SSLContext context = SSLContext.getInstance(protocol);
        context.init(kmf.getKeyManagers(), null, null);
        return context;
    }

    /** Something to do on each round of the loop, e.g. the home server's side. */
    interface Action {
        void run() throws IOException;
    }

    /** The proxy's selector loop for connections under test; the packets they read are collected. */
    static final class Loop implements AutoCloseable {

        final Selector selector;
        final List<byte[]> packets = new ArrayList<>();
        final TlsClient.Packets sink = (buffer, offset, length) -> {
            byte[] p = new byte[length];
            buffer.getBytes(offset, p);
            packets.add(p);
        };
        /** Done on each round after the selected connections: the home server's side. */
        Action each = () -> {};

        Loop() throws IOException {
            selector = Selector.open();
        }

        /** Runs until {@code done} holds; a connection's {@link IOException} ends it as the proxy's loop would. */
        void until(BooleanSupplier done, Duration max) throws IOException {
            long deadline = System.nanoTime() + max.toNanos();
            while (!done.getAsBoolean()) {
                if (System.nanoTime() > deadline) {
                    throw new AssertionError("not done within " + max);
                }
                selector.selectedKeys().clear();
                selector.select(10);
                for (SelectionKey key : selector.selectedKeys()) {
                    if (key.isValid()) {
                        ((HomeConnection) key.attachment()).onSelected(sink);
                    }
                }
                each.run();
            }
        }

        @Override
        public void close() throws IOException {
            selector.close();
        }
    }

    /**
     * A DTLS 1.2 home server on a non-blocking socket, driven by {@link #pump}: it answers the handshake and collects
     * the RADIUS packets it gets; without a context it only counts the datagrams (a home server that does not answer).
     */
    static final class DtlsHome implements AutoCloseable {

        final DatagramChannel channel;
        private final SSLContext context;
        private SSLEngine engine;
        private final ByteBuffer empty = ByteBuffer.allocate(0);
        private SocketAddress peer;
        final List<byte[]> received = new ArrayList<>();
        int datagrams;
        boolean closedByPeer;

        DtlsHome(SSLContext context) throws IOException {
            channel = DatagramChannel.open();
            channel.configureBlocking(false);
            channel.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            this.context = context;
            if (context != null) {
                restart();
            }
        }

        /** A new association for the next ClientHello, as after the old one was closed. */
        void restart() throws IOException {
            engine = context.createSSLEngine();
            engine.setUseClientMode(false);
            engine.setEnabledProtocols(new String[] {"DTLSv1.2"});
            engine.beginHandshake();
            closedByPeer = false;
        }

        InetSocketAddress address() throws IOException {
            return (InetSocketAddress) channel.getLocalAddress();
        }

        /** Reads every datagram that came, answering the handshake. */
        void pump() throws IOException {
            ByteBuffer datagram = ByteBuffer.allocate(1 << 16);
            SocketAddress from;
            while ((from = channel.receive(datagram)) != null) {
                datagrams++;
                peer = from;
                datagram.flip();
                if (engine != null) {
                    unwrap(datagram);
                }
                datagram.clear();
            }
        }

        private void unwrap(ByteBuffer datagram) throws IOException {
            ByteBuffer app = ByteBuffer.allocate(1 << 16);
            while (true) {
                SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
                if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    SslEngines.runTasks(engine);
                    continue;
                }
                if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    wrap(empty);
                    continue;
                }
                if (!datagram.hasRemaining() && hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                    return;
                }
                app.clear();
                SSLEngineResult r = engine.unwrap(datagram, app);
                if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                    closedByPeer = true;
                    return;
                }
                if (r.getStatus() != SSLEngineResult.Status.OK) {
                    return;
                }
                if (r.bytesProduced() > 0) {
                    received.add(Arrays.copyOf(app.array(), app.position()));
                } else if (r.bytesConsumed() == 0
                        && r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    return;
                }
            }
        }

        private void wrap(ByteBuffer plain) throws IOException {
            do {
                ByteBuffer out = ByteBuffer.allocate(1 << 16);
                SSLEngineResult r = engine.wrap(plain, out);
                out.flip();
                if (out.hasRemaining()) {
                    channel.send(out, peer);
                }
                if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                    return;
                }
                if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    SslEngines.runTasks(engine);
                }
            } while (plain.hasRemaining());
        }

        /** Sends {@code plain} in one record. */
        void send(byte[] plain) throws IOException {
            wrap(ByteBuffer.wrap(plain));
        }

        /** Sends a datagram as it is, outside DTLS. */
        void sendRaw(byte[] datagram) throws IOException {
            channel.send(ByteBuffer.wrap(datagram), peer);
        }

        /** Ends the association with close_notify. */
        void closeNotify() throws IOException {
            engine.closeOutbound();
            wrap(empty);
        }

        @Override
        public void close() throws IOException {
            channel.close();
        }
    }
}
