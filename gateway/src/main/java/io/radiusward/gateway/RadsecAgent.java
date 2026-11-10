/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLongArray;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.Agent;
import org.agrona.concurrent.MessageHandler;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RadSec, RADIUS over TLS over TCP (RFC 6614, RFC 6613, ADR 0034), on one thread: a non-blocking selector, the JDK's
 * {@link SSLEngine} per connection, client certificates required. After the handshake the connection is bound to the
 * NAS entry of its source address, which must allow RadSec (and, if configured, be named in the certificate). Each
 * RADIUS packet read from it goes through the {@link RadsecLink} to the agent that decides it — Access-Requests to
 * the {@link AuthAgent}, Accounting-Requests to the {@link UdpAgent}, Status-Server to the first of them — and their
 * replies come back here to be written to the connection they came from. Never blocks: a full ring drops the packet,
 * a peer that does not read its replies is disconnected, a malformed packet closes the connection (RFC 6613 §2.6.4).
 */
final class RadsecAgent implements Agent {

    private static final Logger LOG = LogManager.getLogger(RadsecAgent.class);
    private static final long HOUSEKEEPING_INTERVAL_NS = 100_000_000L;
    private static final int MAX_PENDING_OUTPUT = 1 << 20;

    enum Counter {
        CONNECTIONS_ACCEPTED,
        CONNECTIONS_REFUSED,
        HANDSHAKES_FAILED,
        HANDSHAKES_RESUMED,
        NAS_REFUSED,
        REQUESTS,
        MALFORMED,
        NOT_HANDLED,
        COA_SENT,
        COA_NO_CONNECTION,
        COA_ANSWERS,
        DROPPED,
        REPLIES,
        REPLIES_STALE,
        CONNECTIONS_CLOSED,
        TIMED_OUT
    }

    private final RadsecConfig config;
    private final NasRegistry registry;
    private final RadsecLink link;
    private final Map<String, Integer> clientIndex;
    private final boolean auth;
    private final UdpAgent.NanoClock clock;
    private final List<NasClient> certificateOnly;
    private final Connection[] connections;
    private final int[] generations;
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    private final MessageHandler replyHandler = this::onReply;
    private final MessageHandler coaHandler = this::onCoa;
    private final java.util.concurrent.atomic.AtomicIntegerArray connectedNas;
    private final ByteBuffer reply = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final ByteBuffer empty = ByteBuffer.allocate(0);

    private ServerSocketChannel server;
    private Selector selector;
    private volatile int open;
    private volatile boolean bound;
    private long now;
    private long nextHousekeeping;

    /**
     * @param clientIndex the index in {@link RadsecLink#clients} of each NAS entry allowed over RadSec, by name
     * @param auth whether Access-Requests are answered (otherwise only accounting)
     */
    RadsecAgent(
            RadsecConfig config,
            NasRegistry registry,
            RadsecLink link,
            Map<String, Integer> clientIndex,
            boolean auth,
            UdpAgent.NanoClock clock) {
        this.config = config;
        this.registry = registry;
        this.link = link;
        this.clientIndex = Map.copyOf(clientIndex);
        this.auth = auth;
        this.clock = clock;
        this.certificateOnly = registry.clients().stream()
                .filter(NasClient::certificateOnly)
                .filter(n -> config.clients().containsKey(n.name()))
                .sorted(java.util.Comparator.comparing(NasClient::name))
                .toList();
        this.connectedNas = new java.util.concurrent.atomic.AtomicIntegerArray(Math.max(1, link.clients.length));
        this.connections = new Connection[config.connections()];
        this.generations = new int[config.connections()];
    }

    /** One TLS connection; its buffers are the engine's sizes, the plaintext one holds a packet more. */
    private static final class Connection {
        final int index;
        final int generation;
        final SocketChannel channel;
        final SSLEngine engine;
        final InetSocketAddress remote;
        final long openedAt;
        final long acceptedAt = System.currentTimeMillis(); // to compare with the TLS session's creation time
        SelectionKey key;
        ByteBuffer netIn;
        final ByteBuffer appIn;
        final UnsafeBuffer appView;
        ByteBuffer netOut;
        long lastActivity;
        int nas = -1; // index in RadsecLink.clients once the handshake is done and the NAS known

        Connection(int index, int generation, SocketChannel channel, SSLEngine engine, long now) throws IOException {
            this.index = index;
            this.generation = generation;
            this.channel = channel;
            this.engine = engine;
            this.remote = (InetSocketAddress) channel.getRemoteAddress();
            this.openedAt = now;
            this.lastActivity = now;
            int packetSize = engine.getSession().getPacketBufferSize();
            netIn = ByteBuffer.allocate(packetSize);
            appIn = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() + RadiusPacket.MAX_LENGTH);
            appView = new UnsafeBuffer(appIn);
            netOut = ByteBuffer.allocate(packetSize * 2);
        }

        long route() {
            return RadsecLink.route(index, generation);
        }
    }

    @Override
    public void onStart() {
        try {
            selector = Selector.open();
            server = ServerSocketChannel.open();
            server.bind(new InetSocketAddress(config.host(), config.port()), 128);
            server.configureBlocking(false);
            server.register(selector, SelectionKey.OP_ACCEPT);
            bound = true;
            LOG.info("listening for RadSec on {}", server.getLocalAddress());
        } catch (IOException e) {
            throw new IllegalStateException("cannot bind RadSec socket " + config.host() + ":" + config.port(), e);
        }
    }

    /** Port actually bound (useful when configured as 0). */
    int localPort() {
        try {
            return ((InetSocketAddress) server.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    @Override
    public int doWork() throws IOException {
        now = clock.nanoTime();
        int work = 0;
        if (selector.selectNow() > 0) {
            Iterator<SelectionKey> keys = selector.selectedKeys().iterator();
            while (keys.hasNext()) {
                SelectionKey key = keys.next();
                keys.remove();
                work++;
                if (!key.isValid()) {
                    continue;
                }
                if (key.isAcceptable()) {
                    accept();
                } else if (key.attachment() instanceof Connection c) {
                    try {
                        if (key.isReadable()) {
                            read(c);
                        }
                        if (key.isValid() && key.isWritable()) {
                            flush(c);
                        }
                    } catch (IOException e) {
                        if (c.nas < 0 && !(e instanceof Refused)) {
                            increment(Counter.HANDSHAKES_FAILED);
                            LOG.debug("RadSec handshake with {} failed: {}", c.remote, e.getMessage());
                        }
                        close(c);
                    }
                }
            }
        }
        if (auth) {
            work += link.fromAuth.read(replyHandler, 64);
        }
        work += link.fromAccounting.read(replyHandler, 64);
        work += link.toNas.read(coaHandler, 64);
        if (now - nextHousekeeping >= 0) {
            housekeeping();
            nextHousekeeping = now + HOUSEKEEPING_INTERVAL_NS;
        }
        return work;
    }

    private void accept() throws IOException {
        SocketChannel channel;
        while ((channel = server.accept()) != null) {
            int index = freeIndex();
            if (index < 0) {
                increment(Counter.CONNECTIONS_REFUSED);
                channel.close();
                continue;
            }
            channel.configureBlocking(false);
            channel.setOption(StandardSocketOptions.TCP_NODELAY, true);
            channel.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
            SSLEngine engine = config.credentials().current().createSSLEngine();
            engine.setUseClientMode(false);
            engine.setNeedClientAuth(true);
            engine.setEnabledProtocols(config.versions().toArray(String[]::new));
            Connection c = new Connection(index, generations[index], channel, engine, now);
            engine.beginHandshake();
            c.key = channel.register(selector, SelectionKey.OP_READ, c);
            connections[index] = c;
            open++;
            increment(Counter.CONNECTIONS_ACCEPTED);
        }
    }

    private int freeIndex() {
        for (int i = 0; i < connections.length; i++) {
            if (connections[i] == null) {
                return i;
            }
        }
        return -1;
    }

    private void read(Connection c) throws IOException {
        if (!c.netIn.hasRemaining()) {
            c.netIn = grow(c.netIn, c.engine.getSession().getPacketBufferSize());
        }
        int n = c.channel.read(c.netIn);
        if (n < 0) {
            close(c);
            return;
        }
        c.lastActivity = now;
        c.netIn.flip();
        try {
            progress(c);
        } finally {
            c.netIn.compact();
        }
        if (connections[c.index] == c) {
            flush(c);
        }
    }

    /** Drives the engine over what was read: handshake steps, then decrypted packets to the deciding agents. */
    private void progress(Connection c) throws IOException {
        while (c.channel.isOpen()) {
            SSLEngineResult.HandshakeStatus hs = c.engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task = c.engine.getDelegatedTask()) != null) {
                    task.run(); // certificate checks; OCSP may wait for its timeout (ADR 0033)
                }
                continue;
            }
            if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(c, empty);
                continue;
            }
            if (!c.netIn.hasRemaining() && hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                return;
            }
            SSLEngineResult r = c.engine.unwrap(c.netIn, c.appIn);
            switch (r.getStatus()) {
                case BUFFER_UNDERFLOW -> {
                    return; // the rest of the record is still on its way
                }
                case BUFFER_OVERFLOW -> {
                    dispatch(c);
                    if (c.appIn.remaining() < c.engine.getSession().getApplicationBufferSize()) {
                        throw new SSLException("plaintext buffer full");
                    }
                }
                case CLOSED -> {
                    close(c);
                    return;
                }
                default -> {}
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                established(c);
            }
            dispatch(c);
        }
    }

    /** Encrypts {@code plain} (or a handshake message) into the connection's output. */
    private void wrap(Connection c, ByteBuffer plain) throws IOException {
        do {
            int need = c.engine.getSession().getPacketBufferSize();
            if (c.netOut.remaining() < need) {
                if (c.netOut.capacity() + need > MAX_PENDING_OUTPUT) {
                    throw new IOException("peer does not read its replies");
                }
                c.netOut = grow(c.netOut, need);
            }
            SSLEngineResult r = c.engine.wrap(plain, c.netOut);
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("TLS closed");
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                established(c);
            }
        } while (plain.hasRemaining());
    }

    private static ByteBuffer grow(ByteBuffer buffer, int more) {
        ByteBuffer larger = ByteBuffer.allocate(buffer.capacity() + more);
        buffer.flip();
        larger.put(buffer);
        return larger;
    }

    /** The handshake is done: the connection belongs to the NAS entry of its address, if that allows RadSec. */
    private void established(Connection c) throws IOException {
        if (c.nas >= 0) {
            return;
        }
        X509Certificate certificate = peerCertificate(c.engine);
        NasClient nas = registry.lookup(c.remote.getAddress());
        Integer index = nas == null ? null : clientIndex.get(nas.name());
        RadsecConfig.Client client = index == null ? null : config.clients().get(nas.name());
        if (client == null && certificate != null) { // no entry for the address allows RadSec: by certificate alone
            for (NasClient candidate : certificateOnly) {
                if (CertificateIdentity.matches(
                        certificate, config.clients().get(candidate.name()).identity())) {
                    nas = candidate;
                    index = clientIndex.get(candidate.name());
                    client = config.clients().get(candidate.name());
                    break;
                }
            }
        }
        if (certificate == null
                || client == null
                || (client.identity() != null && !CertificateIdentity.matches(certificate, client.identity()))) {
            increment(Counter.NAS_REFUSED);
            LOG.info(
                    "RadSec connection from {} refused: {}",
                    c.remote,
                    nas == null
                            ? "no NAS entry for the address"
                            : client == null
                                    ? "NAS entry " + nas.name() + " does not allow RadSec"
                                    : "certificate " + certificate.getSubjectX500Principal() + " does not name "
                                            + client.identity());
            throw new Refused();
        }
        c.nas = index;
        connectedNas.incrementAndGet(index);
        if (c.engine.getSession().getCreationTime() < c.acceptedAt) {
            increment(Counter.HANDSHAKES_RESUMED); // a session from an earlier connection
        }
        LOG.info("RadSec connection from {} for NAS {}", c.remote, nas.name());
    }

    /** The handshake succeeded but the NAS may not use RadSec: counted as such, not as a failed handshake. */
    private static final class Refused extends IOException {
        Refused() {
            super("NAS refused");
        }
    }

    private static X509Certificate peerCertificate(SSLEngine engine) {
        try {
            Certificate[] chain = engine.getSession().getPeerCertificates();
            return chain.length > 0 && chain[0] instanceof X509Certificate x ? x : null;
        } catch (SSLPeerUnverifiedException e) {
            return null;
        }
    }

    /** Whole RADIUS packets from the plaintext, each to the agent that decides it. */
    private void dispatch(Connection c) throws IOException {
        ByteBuffer in = c.appIn;
        in.flip();
        try {
            while (in.remaining() >= 4) { // code, identifier, length: enough to judge the length
                int at = in.position();
                int length = in.getShort(at + 2) & 0xFFFF;
                if (length < RadiusPacket.HEADER_LENGTH || length > RadiusPacket.MAX_LENGTH || c.nas < 0) {
                    increment(Counter.MALFORMED);
                    throw new IOException("malformed RADIUS packet over RadSec"); // RFC 6613 §2.6.4: close
                }
                if (in.remaining() < length) {
                    break;
                }
                forward(c, in.get(at) & 0xFF, at, length);
                in.position(at + length);
            }
        } finally {
            in.compact();
        }
    }

    private void forward(Connection c, int code, int offset, int length) {
        if (code == DynamicAuthorization.DISCONNECT_ACK
                || code == DynamicAuthorization.DISCONNECT_NAK
                || code == DynamicAuthorization.COA_ACK
                || code == DynamicAuthorization.COA_NAK) {
            int index = link.fromNas.tryClaim(RadsecLink.PACKET_MSG, 4 + length);
            if (index > 0) {
                link.fromNas.buffer().putInt(index, c.nas);
                link.fromNas.buffer().putBytes(index + 4, c.appView, offset, length);
                link.fromNas.commit(index);
                increment(Counter.COA_ANSWERS);
            } else {
                increment(Counter.DROPPED);
            }
            return;
        }
        increment(Counter.REQUESTS);
        org.agrona.concurrent.ringbuffer.RingBuffer ring = switch (code) {
            case RadiusCode.ACCESS_REQUEST -> auth ? link.toAuth : null;
            case RadiusCode.ACCOUNTING_REQUEST -> link.toAccounting;
            case RadiusCode.STATUS_SERVER -> auth ? link.toAuth : link.toAccounting;
            default -> null;
        };
        if (ring == null) {
            increment(Counter.NOT_HANDLED);
        } else if (!RadsecLink.request(ring, c.route(), c.nas, c.appView, offset, length)) {
            increment(Counter.DROPPED);
        }
    }

    /** Whether a NAS index of {@link RadsecLink#clients} has an established connection (CoA goes there). */
    boolean connected(int nas) {
        return nas >= 0 && nas < connectedNas.length() && connectedNas.get(nas) > 0;
    }

    /** A CoA or Disconnect-Request for a NAS: to its first established connection (RFC 6614 §2.5). */
    private void onCoa(int msgTypeId, DirectBuffer buffer, int index, int length) {
        int nas = buffer.getInt(index);
        for (Connection c : connections) {
            if (c != null && c.nas == nas) {
                reply.clear();
                buffer.getBytes(index + 4, reply, length - 4);
                reply.flip();
                try {
                    wrap(c, reply);
                    increment(Counter.COA_SENT);
                    flush(c);
                } catch (IOException e) {
                    close(c);
                }
                return;
            }
        }
        increment(Counter.COA_NO_CONNECTION); // the request times out at the sender
    }

    /** A reply from a deciding agent: written to its connection if that is still the same one. */
    private void onReply(int msgTypeId, DirectBuffer buffer, int index, int length) {
        long route = buffer.getLong(index);
        int slot = RadsecLink.connection(route);
        Connection c = slot >= 0 && slot < connections.length ? connections[slot] : null;
        if (c == null || c.generation != RadsecLink.generation(route) || c.nas < 0) {
            increment(Counter.REPLIES_STALE);
            return;
        }
        reply.clear();
        buffer.getBytes(index + 8, reply, length - 8);
        reply.flip();
        try {
            wrap(c, reply);
            increment(Counter.REPLIES); // before the flush: the NAS may read it before the counter otherwise
            flush(c);
        } catch (IOException e) {
            close(c);
        }
    }

    private void flush(Connection c) throws IOException {
        c.netOut.flip();
        try {
            c.channel.write(c.netOut);
        } finally {
            c.netOut.compact();
        }
        if (c.key.isValid()) {
            c.key.interestOps(
                    c.netOut.position() > 0 ? SelectionKey.OP_READ | SelectionKey.OP_WRITE : SelectionKey.OP_READ);
        }
    }

    private void housekeeping() {
        long handshake = config.handshakeTimeout().toNanos();
        long idle = config.idleTimeout().toNanos();
        for (Connection c : connections) {
            if (c == null) {
                continue;
            }
            if ((c.nas < 0 && now - c.openedAt > handshake) || (idle > 0 && now - c.lastActivity > idle)) {
                increment(Counter.TIMED_OUT);
                close(c);
            }
        }
    }

    private void close(Connection c) {
        if (connections[c.index] != c) {
            return;
        }
        connections[c.index] = null;
        if (c.nas >= 0) {
            connectedNas.decrementAndGet(c.nas);
        }
        generations[c.index] = (c.generation + 1) & 0x7FFF_FFFF;
        open--;
        increment(Counter.CONNECTIONS_CLOSED);
        try {
            c.engine.closeOutbound();
            c.netOut.clear();
            c.engine.wrap(empty, c.netOut); // close_notify, best effort
            c.netOut.flip();
            c.channel.write(c.netOut);
        } catch (IOException | RuntimeException e) {
            // closing anyway
        }
        try {
            c.key.cancel();
            c.channel.close();
        } catch (IOException e) {
            LOG.debug("closing RadSec connection from {}: {}", c.remote, e.toString());
        }
    }

    private void increment(Counter counter) {
        counts.incrementAndGet(counter.ordinal());
    }

    long get(Counter counter) {
        return counts.get(counter.ordinal());
    }

    boolean bound() {
        return bound;
    }

    int openConnections() {
        return open;
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter("radiusward_gateway_radsec_total", "RadSec connections and packets by what happened to them");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
        }
        w.gauge("radiusward_gateway_radsec_connections", "Open RadSec connections")
                .sample(open, "gateway", gateway);
        w.counter(
                "radiusward_gateway_radsec_tls_reloads_total",
                "Changes of the RadSec certificate, key, CA or CRL files: loaded, or failed (previous kept)");
        w.sample(config.credentials().reloads(), "gateway", gateway, "result", "loaded");
        w.sample(config.credentials().reloadFailures(), "gateway", gateway, "result", "failed");
    }

    @Override
    public void onClose() {
        for (Connection c : connections) {
            if (c != null) {
                close(c);
            }
        }
        try {
            if (server != null) {
                server.close();
            }
            if (selector != null) {
                selector.close();
            }
        } catch (IOException e) {
            LOG.warn("closing the RadSec socket: {}", e.toString());
        }
    }

    @Override
    public String roleName() {
        return "radsec-agent";
    }
}
