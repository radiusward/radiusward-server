/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * One RadSec connection to a home server (RFC 6614, ADR 0037): TLS over TCP as a client, non-blocking, driven by the
 * owner's selector. Our certificate is presented, the home server's must chain to the configured CAs and carry the
 * expected name. RADIUS packets are framed by their length field; until the handshake is done they wait.
 */
final class TlsClient implements HomeConnection {

    /** A whole RADIUS packet read from the connection. */
    interface Packets {
        void packet(UnsafeBuffer buffer, int offset, int length);
    }

    private static final int MAX_PENDING = 1 << 20;

    private final SSLContext context;
    private final String serverName;
    private final InetSocketAddress address;
    private SocketChannel channel;
    private SelectionKey key;
    private SSLEngine engine;
    private ByteBuffer netIn;
    private ByteBuffer appIn;
    private UnsafeBuffer appView;
    private ByteBuffer netOut;
    private ByteBuffer plainOut; // packets written before the handshake finished
    private boolean established;
    private final ByteBuffer empty = ByteBuffer.allocate(0);

    TlsClient(SSLContext context, String serverName, InetSocketAddress address) {
        this.context = context;
        this.serverName = serverName;
        this.address = address;
    }

    /** A TLS client context: our certificate and key (optional), and the CAs the server must chain to. */
    static SSLContext context(Path certificate, Path key, Path ca) {
        return context(certificate, key, ca, "TLS");
    }

    /** The same for {@code protocol} {@code TLS} or {@code DTLS}. */
    static SSLContext context(Path certificate, Path key, Path ca, String protocol) {
        try {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(null, null);
            if (certificate != null && key != null) {
                List<? extends Certificate> chain = TlsCredentials.certificates(certificate);
                keys.setKeyEntry(
                        "client",
                        EapTlsConfig.privateKey(key, "home.tls.key"),
                        new char[0],
                        chain.toArray(Certificate[]::new));
            }
            kmf.init(keys, new char[0]);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            try (InputStream in = Files.newInputStream(ca)) {
                int n = 0;
                for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                    trust.setCertificateEntry("ca-" + n++, c);
                }
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new io.radiusward.common.config.ConfigException("home TLS: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean open() {
        return channel != null && channel.isOpen();
    }

    boolean established() {
        return established && open();
    }

    /** Starts connecting; progress comes through {@link #onSelected}. */
    @Override
    public void connect(Selector selector) throws IOException {
        close();
        channel = SocketChannel.open();
        channel.configureBlocking(false);
        engine = context.createSSLEngine(serverName, address.getPort());
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[] {"TLSv1.2", "TLSv1.3"});
        SSLParameters params = engine.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS"); // the certificate must name serverName
        if (!serverName.isEmpty() && !Character.isDigit(serverName.charAt(0)) && serverName.indexOf(':') < 0) {
            params.setServerNames(List.of(new SNIHostName(serverName)));
        }
        engine.setSSLParameters(params);
        int packetSize = engine.getSession().getPacketBufferSize();
        netIn = ByteBuffer.allocate(packetSize);
        appIn = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() + RadiusPacket.MAX_LENGTH);
        appView = new UnsafeBuffer(appIn);
        netOut = ByteBuffer.allocate(packetSize * 2);
        plainOut = ByteBuffer.allocate(16 * RadiusPacket.MAX_LENGTH);
        established = false;
        boolean connected = channel.connect(address);
        key = channel.register(selector, connected ? SelectionKey.OP_READ : SelectionKey.OP_CONNECT, this);
        if (connected) {
            engine.beginHandshake();
            drive(null);
            flush();
        }
    }

    /** Queues a packet; {@code false} if the connection cannot take more (the request is dropped). */
    @Override
    public boolean send(DirectBuffer packet, int offset, int length) throws IOException {
        if (!open()) {
            return false;
        }
        if (!established) {
            if (plainOut.remaining() < length) {
                return false;
            }
            for (int i = 0; i < length; i++) {
                plainOut.put(packet.getByte(offset + i));
            }
            return true;
        }
        ByteBuffer plain = ByteBuffer.allocate(length);
        packet.getBytes(offset, plain, length);
        plain.flip();
        wrap(plain);
        flush();
        return true;
    }

    /** The selector picked this connection: connect, read, write; whole packets go to {@code packets}. */
    @Override
    public void onSelected(Packets packets) throws IOException {
        if (key.isConnectable()) {
            if (!channel.finishConnect()) {
                return;
            }
            key.interestOps(SelectionKey.OP_READ);
            engine.beginHandshake();
            drive(packets);
            flush();
            return;
        }
        if (key.isReadable()) {
            int n = channel.read(netIn);
            if (n < 0) {
                throw new IOException("closed by the home server");
            }
            netIn.flip();
            try {
                progress(packets);
            } finally {
                netIn.compact();
            }
        }
        if (open()) {
            flush();
        }
    }

    /** Drives the engine with nothing read yet (the handshake's first flight): the read buffer stays as it is. */
    private void drive(Packets packets) throws IOException {
        netIn.flip();
        try {
            progress(packets);
        } finally {
            netIn.compact();
        }
    }

    private void progress(Packets packets) throws IOException {
        while (open()) {
            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    task.run();
                }
                continue;
            }
            if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(empty);
                continue;
            }
            if (!netIn.hasRemaining() && hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                return;
            }
            SSLEngineResult r = engine.unwrap(netIn, appIn);
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                return;
            }
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new IOException("TLS closed by the home server");
            }
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                throw new SSLException("plaintext buffer full");
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                finished();
            }
            if (packets != null) {
                dispatch(packets);
            }
        }
    }

    private void finished() throws IOException {
        if (established) {
            return;
        }
        established = true;
        plainOut.flip();
        if (plainOut.hasRemaining()) {
            wrap(plainOut);
        }
        plainOut.clear();
    }

    private void wrap(ByteBuffer plain) throws IOException {
        do {
            int need = engine.getSession().getPacketBufferSize();
            if (netOut.remaining() < need) {
                if (netOut.capacity() + need > MAX_PENDING) {
                    throw new IOException("home server does not read");
                }
                ByteBuffer larger = ByteBuffer.allocate(netOut.capacity() + need);
                netOut.flip();
                larger.put(netOut);
                netOut = larger;
            }
            SSLEngineResult r = engine.wrap(plain, netOut);
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("TLS closed");
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                finished();
            }
        } while (plain.hasRemaining());
    }

    private void dispatch(Packets packets) throws IOException {
        appIn.flip();
        try {
            while (appIn.remaining() >= 4) {
                int at = appIn.position();
                int length = appIn.getShort(at + 2) & 0xFFFF;
                if (length < RadiusPacket.HEADER_LENGTH || length > RadiusPacket.MAX_LENGTH) {
                    throw new IOException("malformed RADIUS packet from the home server");
                }
                if (appIn.remaining() < length) {
                    break;
                }
                packets.packet(appView, at, length);
                appIn.position(at + length);
            }
        } finally {
            appIn.compact();
        }
    }

    private void flush() throws IOException {
        netOut.flip();
        try {
            channel.write(netOut);
        } finally {
            netOut.compact();
        }
        if (key != null && key.isValid() && (key.interestOps() & SelectionKey.OP_CONNECT) == 0) {
            key.interestOps(
                    netOut.position() > 0 ? SelectionKey.OP_READ | SelectionKey.OP_WRITE : SelectionKey.OP_READ);
        }
    }

    @Override
    public void close() {
        established = false;
        if (channel != null) {
            try {
                if (engine != null) {
                    engine.closeOutbound();
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
