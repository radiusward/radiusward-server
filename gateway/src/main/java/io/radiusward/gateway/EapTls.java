/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * EAP-TLS (RFC 5216, TLS 1.3: RFC 9190, ADR 0028): a TLS handshake with a required client certificate, carried in EAP
 * messages. The JDK's {@link SSLEngine} does the TLS; this class frames it:
 *
 * <ul>
 *   <li>fragments: a message larger than {@code fragmentSize} goes out in pieces, the first with the L flag and the total
 *       length, all but the last with M; the peer acknowledges each with an empty response. The peer's fragments are
 *       acknowledged and joined, up to {@code maxMessage}.
 *   <li>success: after the server's last flight is acknowledged — for TLS 1.2 its Finished, for TLS 1.3 the
 *       one-byte commitment message after the client's Finished.
 *   <li>keys: 128 bytes from the TLS exporter, label {@code client EAP encryption} (TLS 1.2) or {@code
 *       EXPORTER_EAP_TLS_Key_Material} with the type as context (TLS 1.3); the MSK is the first 64.
 * </ul>
 */
final class EapTls implements EapMethod {

    private static final Logger LOG = LogManager.getLogger(EapTls.class);

    static final int TYPE = 13;
    static final int FLAG_LENGTH = 0x80;
    static final int FLAG_MORE = 0x40;
    static final int FLAG_START = 0x20;

    private final EapTlsConfig config;
    private SSLEngine engine;
    private final ByteArrayOutputStream incoming = new ByteArrayOutputStream();
    private byte[] outgoing;
    private int sent;
    private boolean finished;
    private byte[] msk;

    EapTls(EapTlsConfig config) {
        this.config = config;
    }

    @Override
    public int type() {
        return TYPE;
    }

    @Override
    public Step start(int identifier, Credentials credentials) {
        engine = config.context().createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);
        engine.setEnabledProtocols(config.versions().toArray(String[]::new));
        try {
            engine.beginHandshake();
        } catch (SSLException e) {
            return Step.FAILED;
        }
        return Step.next(new byte[] {(byte) FLAG_START});
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        if (data.length < 1) {
            return Step.FAILED;
        }
        int flags = data[0] & 0xFF;
        int offset = 1;
        if ((flags & FLAG_LENGTH) != 0) {
            if (data.length < 5) {
                return Step.FAILED;
            }
            long total =
                    ((data[1] & 0xFFL) << 24) | ((data[2] & 0xFF) << 16) | ((data[3] & 0xFF) << 8) | (data[4] & 0xFF);
            if (total > config.maxMessage()) {
                return Step.FAILED;
            }
            offset = 5;
        }
        int payload = data.length - offset;
        if (outgoing != null) {
            if (sent < outgoing.length) {
                return payload == 0 ? nextFragment() : Step.FAILED; // the peer acknowledges our fragments
            }
            outgoing = null; // our last message is through; what comes now answers it
            if (finished) {
                return payload == 0 ? Step.succeeded(msk) : Step.FAILED;
            }
        }
        if (incoming.size() + payload > config.maxMessage()) {
            return Step.FAILED;
        }
        incoming.write(data, offset, payload);
        if ((flags & FLAG_MORE) != 0) {
            return Step.next(new byte[] {0}); // acknowledge, wait for the rest
        }
        byte[] message = incoming.toByteArray();
        incoming.reset();
        try {
            outgoing = drive(message);
        } catch (SSLException e) {
            LOG.debug("EAP-TLS handshake failed: {}", e.getMessage());
            return Step.FAILED;
        }
        sent = 0;
        if (outgoing.length == 0) {
            return Step.FAILED; // nothing to say and not done: the peer is not following the protocol
        }
        return nextFragment();
    }

    private Step nextFragment() {
        int length = Math.min(config.fragmentSize(), outgoing.length - sent);
        boolean first = sent == 0;
        boolean more = sent + length < outgoing.length;
        boolean announce = first && more;
        byte[] data = new byte[1 + (announce ? 4 : 0) + length];
        data[0] = (byte) ((announce ? FLAG_LENGTH : 0) | (more ? FLAG_MORE : 0));
        int at = 1;
        if (announce) {
            data[1] = (byte) (outgoing.length >>> 24);
            data[2] = (byte) (outgoing.length >>> 16);
            data[3] = (byte) (outgoing.length >>> 8);
            data[4] = (byte) outgoing.length;
            at = 5;
        }
        System.arraycopy(outgoing, sent, data, at, length);
        sent += length;
        return Step.next(data);
    }

    /** Feeds the peer's TLS records to the engine; returns the records to send back. */
    private byte[] drive(byte[] message) throws SSLException {
        ByteBuffer in = ByteBuffer.wrap(message);
        ByteBuffer app = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
        ByteBuffer net = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            SSLEngineResult result;
            switch (engine.getHandshakeStatus()) {
                case NEED_TASK -> {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    continue;
                }
                case NEED_WRAP -> {
                    net.clear();
                    result = engine.wrap(ByteBuffer.allocate(0), net);
                    net.flip();
                    out.write(net.array(), 0, net.limit());
                }
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    if (!in.hasRemaining()
                            && engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        return out.toByteArray(); // the peer's turn
                    }
                    app.clear();
                    result = engine.unwrap(in, app);
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        throw new SSLException("incomplete TLS record from the peer");
                    }
                }
                default -> {
                    // not handshaking: anything left is after the handshake (none is expected)
                    if (in.hasRemaining()) {
                        app.clear();
                        engine.unwrap(in, app);
                        continue;
                    }
                    return out.toByteArray();
                }
            }
            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                completed(out, net);
            }
        }
    }

    /** The handshake is done: derive the keys; TLS 1.3 adds the commitment message (RFC 9190 §2.5). */
    private void completed(ByteArrayOutputStream out, ByteBuffer net) throws SSLException {
        ExtendedSSLSession session = (ExtendedSSLSession) engine.getSession();
        byte[] material;
        if (session.getProtocol().equals("TLSv1.3")) {
            material = session.exportKeyingMaterialData("EXPORTER_EAP_TLS_Key_Material", new byte[] {TYPE}, 128);
            ByteBuffer commitment = ByteBuffer.wrap(new byte[] {0});
            while (commitment.hasRemaining()) {
                net.clear();
                engine.wrap(commitment, net);
                net.flip();
                out.write(net.array(), 0, net.limit());
            }
        } else {
            material = session.exportKeyingMaterialData("client EAP encryption", null, 128);
        }
        msk = Arrays.copyOf(material, 64);
        finished = true;
    }

    /** The client's certificate subject, once known (for logs and future policy). */
    String peer() {
        try {
            return engine.getSession().getPeerPrincipal().getName();
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            return null;
        }
    }
}
