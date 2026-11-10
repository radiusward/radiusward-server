/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * RADIUS over DTLS 1.2 to a home server (RFC 7360, ADR 0055): one association on a connected UDP socket, one RADIUS
 * packet per record. Handshake flights are sent again on a doubling timer (RFC 6347 §4.2.4); packets written before
 * the handshake finished wait for it. Records may be lost like datagrams: the proxy retransmits requests as over UDP.
 */
final class HomeDtlsClient implements HomeConnection {

    /** First handshake retransmission; doubled up to 8 times. */
    static final long RETRANSMIT_NANOS = 1_000_000_000L;
    /** A handshake not finished by then is given up; the next request starts another. */
    static final long HANDSHAKE_NANOS = 15_000_000_000L;

    private final SSLContext context;
    private final String serverName;
    private final InetSocketAddress address;
    private final ByteBuffer datagramIn = ByteBuffer.allocate(1 << 16);
    private final ByteBuffer datagramOut = ByteBuffer.allocate(1 << 16);
    private final ByteBuffer pending = ByteBuffer.allocate(16 * RadiusPacket.MAX_LENGTH);
    private final ByteBuffer empty = ByteBuffer.allocate(0);
    private DatagramChannel channel;
    private SelectionKey key;
    private SSLEngine engine;
    private ByteBuffer appIn;
    private UnsafeBuffer appView;
    private boolean established;
    private long startedAt;
    private long nextRetransmit;
    private long interval;

    HomeDtlsClient(SSLContext context, String serverName, InetSocketAddress address) {
        this.context = context;
        this.serverName = serverName;
        this.address = address;
    }

    @Override
    public boolean open() {
        return channel != null && channel.isOpen();
    }

    @Override
    public boolean lossy() {
        return true;
    }

    @Override
    public void connect(Selector selector) throws IOException {
        close();
        channel = DatagramChannel.open();
        channel.configureBlocking(false);
        channel.connect(address);
        key = channel.register(selector, SelectionKey.OP_READ, this);
        engine = context.createSSLEngine(serverName, address.getPort());
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[] {"DTLSv1.2"});
        SSLParameters params = engine.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS"); // the certificate must name serverName
        if (!serverName.isEmpty() && !Character.isDigit(serverName.charAt(0)) && serverName.indexOf(':') < 0) {
            params.setServerNames(List.of(new SNIHostName(serverName)));
        }
        engine.setSSLParameters(params);
        appIn = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() + RadiusPacket.MAX_LENGTH);
        appView = new UnsafeBuffer(appIn);
        pending.clear();
        established = false;
        startedAt = System.nanoTime();
        interval = RETRANSMIT_NANOS;
        nextRetransmit = startedAt + interval;
        engine.beginHandshake();
        handshake(null);
    }

    @Override
    public boolean send(DirectBuffer packet, int offset, int length) throws IOException {
        if (!open()) {
            return false;
        }
        if (!established) {
            if (pending.remaining() < length) {
                return false;
            }
            packet.getBytes(offset, pending, length);
            return true;
        }
        ByteBuffer plain = ByteBuffer.allocate(length);
        packet.getBytes(offset, plain, length);
        plain.flip();
        wrap(plain);
        return true;
    }

    @Override
    public void onSelected(TlsClient.Packets packets) throws IOException {
        for (int i = 0; i < 64 && open(); i++) {
            datagramIn.clear();
            int n = channel.read(datagramIn);
            if (n <= 0) {
                return;
            }
            datagramIn.flip();
            unwrap(packets);
        }
    }

    private void unwrap(TlsClient.Packets packets) throws IOException {
        while (open()) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runTasks();
                continue;
            }
            if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(empty);
                continue;
            }
            if (!datagramIn.hasRemaining() && hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                return;
            }
            appIn.clear();
            SSLEngineResult r = engine.unwrap(datagramIn, appIn);
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new IOException("DTLS closed by the home server");
            }
            if (r.getStatus() != SSLEngineResult.Status.OK) {
                return; // a record that does not fit: dropped, as a datagram may be
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                finished();
            }
            if (r.bytesProduced() > 0 && packets != null) {
                int length = r.bytesProduced() >= 4 ? appView.getShort(2, java.nio.ByteOrder.BIG_ENDIAN) & 0xFFFF : -1;
                if (length >= RadiusPacket.HEADER_LENGTH && length <= r.bytesProduced()) {
                    packets.packet(appView, 0, length); // else discarded, as over UDP
                }
            } else if (r.bytesConsumed() == 0
                    && r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                return;
            }
        }
    }

    private void handshake(TlsClient.Packets packets) throws IOException {
        while (open()) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runTasks();
            } else if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(empty);
            } else {
                return;
            }
        }
    }

    private void runTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    /** Encrypts {@code plain} or the next handshake record, and sends each datagram the engine makes. */
    private void wrap(ByteBuffer plain) throws IOException {
        do {
            datagramOut.clear();
            SSLEngineResult r = engine.wrap(plain, datagramOut);
            datagramOut.flip();
            if (datagramOut.hasRemaining()) {
                channel.write(datagramOut); // a full socket buffer drops it: retransmission covers it
            }
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("DTLS closed");
            }
            if (r.getStatus() != SSLEngineResult.Status.OK) {
                throw new SSLException("DTLS record does not fit: " + r.getStatus());
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                finished();
            }
        } while (plain.hasRemaining());
    }

    private void finished() throws IOException {
        if (established) {
            return;
        }
        established = true;
        pending.flip();
        while (pending.remaining() >= 4) {
            int length = pending.getShort(pending.position() + 2) & 0xFFFF;
            ByteBuffer one = pending.slice(pending.position(), length);
            pending.position(pending.position() + length);
            wrap(one); // one RADIUS packet per record
        }
        pending.clear();
    }

    @Override
    public void tick(long now) throws IOException {
        if (!open() || established) {
            return;
        }
        if (now - startedAt > HANDSHAKE_NANOS) {
            close();
            return;
        }
        if (now - nextRetransmit >= 0) {
            interval = Math.min(interval * 2, RETRANSMIT_NANOS * 8);
            nextRetransmit = now + interval;
            do {
                wrap(empty); // the JDK sends its last flight again when wrapping while it waits for the peer
                if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    runTasks();
                }
            } while (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP);
        }
    }

    @Override
    public void close() {
        established = false;
        if (channel != null) {
            try {
                if (engine != null) {
                    engine.closeOutbound();
                    try {
                        wrap(empty); // close_notify
                    } catch (IOException | RuntimeException e) {
                        // closing anyway
                    }
                }
                if (key != null) {
                    key.cancel();
                }
                channel.close();
            } catch (IOException e) {
                // closing anyway
            }
        }
        channel = null;
        key = null;
    }
}
