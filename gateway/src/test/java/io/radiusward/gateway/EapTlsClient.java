/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

/**
 * The peer side of EAP-TLS for tests: a JDK TLS client in EAP-TLS framing, with its own fragment size, answering one
 * EAP-TLS request at a time.
 */
final class EapTlsClient {

    private final SSLEngine engine;
    private final int fragmentSize;
    private final java.util.function.UnaryOperator<byte[]> tunnel;
    private final ByteArrayOutputStream incoming = new ByteArrayOutputStream();
    private byte[] outgoing;
    private int sent;

    EapTlsClient(SSLContext context, String protocol, int fragmentSize) {
        this(context, protocol, fragmentSize, null);
    }

    /** With {@code tunnel}: what the peer answers to application data inside the tunnel (PEAP, TTLS). */
    EapTlsClient(
            SSLContext context, String protocol, int fragmentSize, java.util.function.UnaryOperator<byte[]> tunnel) {
        engine = context.createSSLEngine("radius.test", 0);
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[] {protocol});
        this.fragmentSize = fragmentSize;
        this.tunnel = tunnel;
    }

    private final ByteArrayOutputStream application = new ByteArrayOutputStream();

    /** The type data answering the server's EAP-TLS request type data. */
    byte[] answer(byte[] request) throws Exception {
        int flags = request[0] & 0xFF;
        int offset = (flags & EapTls.FLAG_LENGTH) != 0 ? 5 : 1;
        if ((flags & EapTls.FLAG_START) != 0) {
            engine.beginHandshake();
            outgoing = drive(new byte[0]);
            sent = 0;
            return fragment();
        }
        int payload = request.length - offset;
        if (outgoing != null && sent < outgoing.length) {
            return fragment(); // the server acknowledged a fragment of ours
        }
        incoming.write(request, offset, payload);
        if ((flags & EapTls.FLAG_MORE) != 0) {
            return new byte[] {0};
        }
        byte[] message = incoming.toByteArray();
        incoming.reset();
        application.reset();
        outgoing = drive(message);
        if (application.size() > 0 && tunnel != null) {
            byte[] plain = tunnel.apply(application.toByteArray());
            if (plain != null) {
                ByteArrayOutputStream records = new ByteArrayOutputStream();
                records.write(outgoing);
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
        data[0] = (byte) ((announce ? EapTls.FLAG_LENGTH : 0) | (more ? EapTls.FLAG_MORE : 0));
        int at = 1;
        if (announce) {
            ByteBuffer.wrap(data, 1, 4).putInt(outgoing.length);
            at = 5;
        }
        System.arraycopy(outgoing, sent, data, at, length);
        sent += length;
        return data;
    }

    private byte[] drive(byte[] message) throws Exception {
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
                        throw new IllegalStateException("incomplete record");
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

    /** The MSK as the client derives it, to compare with what the server sent. */
    byte[] msk() throws Exception {
        return msk(13);
    }

    byte[] msk(int type) throws Exception {
        ExtendedSSLSession session = (ExtendedSSLSession) engine.getSession();
        byte[] material = session.getProtocol().equals("TLSv1.3")
                ? session.exportKeyingMaterialData("EXPORTER_EAP_TLS_Key_Material", new byte[] {(byte) type}, 128)
                : session.exportKeyingMaterialData("client EAP encryption", null, 128);
        return Arrays.copyOf(material, 64);
    }
}
