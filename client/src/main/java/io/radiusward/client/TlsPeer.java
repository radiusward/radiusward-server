/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.UnaryOperator;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

/**
 * The peer side of a TLS-based EAP method (EAP-TLS, PEAP, TTLS): the JDK's TLS client in RFC 5216 framing, with
 * fragments of its own size, answering one request's type data at a time; inside the tunnel, {@code tunnel} answers
 * the server's application data (PEAP, TTLS).
 */
final class TlsPeer {

    static final int FLAG_LENGTH = 0x80;
    static final int FLAG_MORE = 0x40;
    static final int FLAG_START = 0x20;

    private final SSLEngine engine;
    private final int fragmentSize;
    private final UnaryOperator<byte[]> tunnel;
    private final ByteArrayOutputStream incoming = new ByteArrayOutputStream();
    private final ByteArrayOutputStream application = new ByteArrayOutputStream();
    private byte[] outgoing;
    private int sent;
    private boolean tunnelStarted;

    TlsPeer(SSLContext context, String protocol, int fragmentSize, UnaryOperator<byte[]> tunnel) {
        engine = context.createSSLEngine();
        engine.setUseClientMode(true);
        if (protocol != null) {
            engine.setEnabledProtocols(new String[] {protocol});
        }
        this.fragmentSize = fragmentSize;
        this.tunnel = tunnel;
    }

    /** Keying material of the TLS session: TTLS's implicit challenge. */
    byte[] export(String label, int length) throws SSLException {
        return ((ExtendedSSLSession) engine.getSession()).exportKeyingMaterialData(label, null, length);
    }

    /** Whether the handshake finished. */
    boolean established() {
        return engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                && engine.getSession().isValid();
    }

    /** The type data answering the server's request type data. */
    byte[] answer(byte[] request) throws SSLException {
        int flags = request.length == 0 ? 0 : request[0] & 0xFF;
        int offset = (flags & FLAG_LENGTH) != 0 ? 5 : 1;
        if ((flags & FLAG_START) != 0) {
            engine.beginHandshake();
            outgoing = drive(new byte[0]);
            sent = 0;
            return fragment();
        }
        if (outgoing != null && sent < outgoing.length) {
            return fragment(); // the server acknowledged a fragment of ours
        }
        if (request.length > offset) {
            incoming.write(request, offset, request.length - offset);
        }
        if ((flags & FLAG_MORE) != 0) {
            return new byte[] {0}; // acknowledge the server's fragment
        }
        byte[] message = incoming.toByteArray();
        incoming.reset();
        application.reset();
        outgoing = drive(message);
        if (tunnel != null && established() && (application.size() > 0 || !tunnelStarted)) {
            tunnelStarted = true;
            byte[] plain = tunnel.apply(application.toByteArray()); // empty: the peer may speak first (TTLS)
            if (plain != null && plain.length > 0) {
                ByteArrayOutputStream records = new ByteArrayOutputStream();
                records.writeBytes(outgoing);
                ByteBuffer in = ByteBuffer.wrap(plain);
                ByteBuffer net = ByteBuffer.allocate(64 * 1024);
                while (in.hasRemaining()) {
                    net.clear();
                    engine.wrap(in, net);
                    net.flip();
                    records.write(net.array(), 0, net.limit());
                }
                outgoing = records.toByteArray();
            }
        }
        sent = 0;
        return outgoing.length == 0 ? new byte[] {0} : fragment();
    }

    private byte[] fragment() {
        int length = Math.min(fragmentSize, outgoing.length - sent);
        boolean more = sent + length < outgoing.length;
        boolean announce = sent == 0 && more;
        byte[] data = new byte[1 + (announce ? 4 : 0) + length];
        data[0] = (byte) ((announce ? FLAG_LENGTH : 0) | (more ? FLAG_MORE : 0));
        int at = 1;
        if (announce) {
            ByteBuffer.wrap(data, 1, 4).putInt(outgoing.length);
            at = 5;
        }
        System.arraycopy(outgoing, sent, data, at, length);
        sent += length;
        return data;
    }

    private byte[] drive(byte[] message) throws SSLException {
        ByteBuffer in = ByteBuffer.wrap(message);
        ByteBuffer app = ByteBuffer.allocate(64 * 1024);
        ByteBuffer net = ByteBuffer.allocate(64 * 1024);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            switch (engine.getHandshakeStatus()) {
                case NEED_TASK -> {
                    Runnable t;
                    while ((t = engine.getDelegatedTask()) != null) {
                        t.run();
                    }
                }
                case NEED_WRAP -> {
                    net.clear();
                    engine.wrap(ByteBuffer.allocate(0), net);
                    net.flip();
                    out.write(net.array(), 0, net.limit());
                }
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    if (!in.hasRemaining()) {
                        return out.toByteArray();
                    }
                    app.clear();
                    SSLEngineResult r = engine.unwrap(in, app);
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        throw new SSLException("incomplete TLS record from the server");
                    }
                    app.flip();
                    application.write(app.array(), 0, app.limit());
                }
                default -> {
                    while (in.hasRemaining()) { // after the handshake: tickets, the commitment, tunnel data
                        app.clear();
                        engine.unwrap(in, app);
                        app.flip();
                        application.write(app.array(), 0, app.limit());
                    }
                    return out.toByteArray();
                }
            }
        }
    }

    /**
     * The MSK as the peer derives it: RFC 5216 or RFC 5281 under TLS 1.2 (the method's label), RFC 9190 / RFC 9427
     * under TLS 1.3 (the EAP type as context).
     */
    byte[] msk(int type, String tls12Label) throws SSLException {
        ExtendedSSLSession session = (ExtendedSSLSession) engine.getSession();
        byte[] material = session.getProtocol().equals("TLSv1.3")
                ? session.exportKeyingMaterialData("EXPORTER_EAP_TLS_Key_Material", new byte[] {(byte) type}, 128)
                : session.exportKeyingMaterialData(tls12Label, null, 128);
        return Arrays.copyOf(material, 64);
    }
}
