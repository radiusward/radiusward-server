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
 * The TLS part shared by EAP-TLS, PEAP and TTLS (ADR 0028, 0029): the JDK's {@link SSLEngine} in the RFC 5216 framing
 * — fragments with the L and M flags, the peer's acknowledgements, reassembly up to a limit — and the keys from the
 * TLS exporter. What happens once the handshake is done is up to the method: {@link #onFinished}, {@link #onAck},
 * {@link #onData}.
 */
abstract class TlsTunnel implements EapMethod {

    private static final Logger LOG = LogManager.getLogger(TlsTunnel.class);

    static final int FLAG_LENGTH = 0x80;
    static final int FLAG_MORE = 0x40;
    static final int FLAG_START = 0x20;

    final EapTlsConfig config;
    private SSLEngine engine;
    private final ByteArrayOutputStream incoming = new ByteArrayOutputStream();
    private byte[] outgoing;
    private int sent;
    private boolean finished;
    private byte[] msk;
    private byte[] retryData; // a message whose inner check could not be answered: only its retransmission may come

    TlsTunnel(EapTlsConfig config) {
        this.config = config;
    }

    /** Whether the peer must present a certificate (EAP-TLS), or the tunnel authenticates only the server. */
    abstract boolean clientCertificate();

    /** The TLS 1.2 exporter label of the method's keys. */
    abstract String keyLabel();

    /**
     * The handshake just completed. Returns application data to send right away (e.g. TLS 1.3's commitment message or
     * the first inner request), or {@code null} to wait for the peer's acknowledgement of the last flight.
     */
    abstract byte[] onFinished(boolean tls13);

    /** The peer acknowledged our last message after the handshake. */
    abstract Step onAck(Credentials credentials);

    /** Application data from the peer, decrypted. */
    abstract Step onData(byte[] data, Credentials credentials);

    /**
     * The peer retransmitted the message whose inner check was {@link Step#UNAVAILABLE}: repeat that check (its TLS
     * records cannot be decrypted twice).
     */
    Step onRetry(Credentials credentials) {
        return Step.FAILED;
    }

    final byte[] msk() {
        return msk;
    }

    @Override
    public Step start(int identifier, Credentials credentials) {
        engine = config.context().createSSLEngine();
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(clientCertificate());
        engine.setEnabledProtocols(config.versions().toArray(String[]::new));
        try {
            engine.beginHandshake();
        } catch (SSLException e) {
            return Step.FAILED;
        }
        return Step.next(new byte[] {(byte) FLAG_START});
    }

    @Override
    public final Step process(int identifier, byte[] data, Credentials credentials) {
        if (data.length < 1) {
            return Step.FAILED;
        }
        if (retryData != null) {
            if (!Arrays.equals(data, retryData)) {
                return Step.FAILED;
            }
            Step step = onRetry(credentials);
            if (!step.unavailable()) {
                retryData = null;
            }
            return step;
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
            if (finished && payload == 0) {
                return onAck(credentials);
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
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream application = new ByteArrayOutputStream();
        boolean wasFinished = finished;
        try {
            drive(message, out, application);
            if (!wasFinished && finished) {
                byte[] first = onFinished(engine.getSession().getProtocol().equals("TLSv1.3"));
                if (first != null) {
                    wrapApplication(first, out);
                }
            }
        } catch (SSLException e) {
            LOG.debug("EAP TLS failed: {}", e.getMessage());
            return Step.FAILED;
        }
        if (wasFinished && application.size() > 0) {
            Step step = onData(application.toByteArray(), credentials);
            if (step.unavailable()) {
                retryData = data.clone();
                return step;
            }
            if (out.size() == 0 || step.done()) {
                return step;
            }
        }
        return send(out.toByteArray());
    }

    /** Sends TLS records (already wrapped). */
    final Step send(byte[] records) {
        if (records.length == 0) {
            return Step.FAILED; // nothing to say and not done: the peer is not following the protocol
        }
        outgoing = records;
        sent = 0;
        return nextFragment();
    }

    /** Encrypts {@code plain} as application data and sends it. */
    final Step sendApplication(byte[] plain) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            wrapApplication(plain, out);
        } catch (SSLException e) {
            return Step.FAILED;
        }
        return send(out.toByteArray());
    }

    private void wrapApplication(byte[] plain, ByteArrayOutputStream out) throws SSLException {
        ByteBuffer in = ByteBuffer.wrap(plain);
        ByteBuffer net = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
        do {
            net.clear();
            engine.wrap(in, net);
            net.flip();
            out.write(net.array(), 0, net.limit());
        } while (in.hasRemaining());
    }

    private Step nextFragment() {
        int length = Math.min(config.fragmentSize(), outgoing.length - sent);
        boolean more = sent + length < outgoing.length;
        boolean announce = sent == 0 && more;
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

    /** Feeds the peer's TLS records to the engine: handshake output to {@code out}, decrypted data to {@code app}. */
    private void drive(byte[] message, ByteArrayOutputStream out, ByteArrayOutputStream application)
            throws SSLException {
        ByteBuffer in = ByteBuffer.wrap(message);
        ByteBuffer app = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize());
        ByteBuffer net = ByteBuffer.allocate(engine.getSession().getPacketBufferSize());
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
                        return; // the peer's turn
                    }
                    app.clear();
                    result = engine.unwrap(in, app);
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        throw new SSLException("incomplete TLS record from the peer");
                    }
                    app.flip();
                    application.write(app.array(), 0, app.limit());
                }
                default -> {
                    if (!in.hasRemaining()) {
                        return;
                    }
                    app.clear();
                    result = engine.unwrap(in, app);
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        throw new SSLException("incomplete TLS record from the peer");
                    }
                    app.flip();
                    application.write(app.array(), 0, app.limit());
                }
            }
            if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED && !finished) {
                keys();
            }
        }
    }

    /** RFC 5216 (TLS 1.2: the method's label, no context) or RFC 9190 / RFC 9427 (TLS 1.3: the EAP type). */
    private void keys() throws SSLException {
        ExtendedSSLSession session = (ExtendedSSLSession) engine.getSession();
        byte[] material = session.getProtocol().equals("TLSv1.3")
                ? session.exportKeyingMaterialData("EXPORTER_EAP_TLS_Key_Material", new byte[] {(byte) type()}, 128)
                : session.exportKeyingMaterialData(keyLabel(), null, 128);
        msk = Arrays.copyOf(material, 64);
        finished = true;
    }

    /** The client's certificate subject, if it presented one. */
    final String peer() {
        try {
            return engine.getSession().getPeerPrincipal().getName();
        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            return null;
        }
    }
}
