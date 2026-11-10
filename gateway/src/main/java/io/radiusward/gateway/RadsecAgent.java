/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
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
 *
 * <p>RADIUS over DTLS 1.2 (RFC 7360, ADR 0038) on a UDP socket of the same selector: one association per NAS address
 * and port, each with its {@link SSLEngine}, its NAS entry bound after the handshake as for TCP, one RADIUS packet per
 * record. Associations take the route slots after the TCP connections, so replies and CoA requests find them the same
 * way. Handshake flights are retransmitted on a doubling timer (RFC 6347 §4.2.4); a new ClientHello from the address
 * of an established association replaces it (the NAS restarted, §4.2.8); datagrams that are not DTLS, or not from an
 * association or a ClientHello, are silently discarded.
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
        TIMED_OUT,
        /** DTLS: a handshake flight sent again after its retransmission timer. */
        RETRANSMISSIONS,
        /** DTLS: a datagram from an address without an association that is no ClientHello. */
        NOT_ASSOCIATED,
        /** DTLS: an established association replaced by a new ClientHello from its address. */
        RESTARTED
    }

    private final RadsecConfig config;
    private final NasRegistry registry;
    private final RadsecLink link;
    private final Map<String, Integer> clientIndex;
    private final Map<String, Integer> dtlsIndex;
    private final boolean auth;
    private final UdpAgent.NanoClock clock;
    private final List<NasClient> certificateOnly;
    private final List<NasClient> dtlsCertificateOnly;
    private final Connection[] connections;
    private final int[] generations;
    private final Association[] associations;
    private final int[] dtlsGenerations;
    private final Map<InetSocketAddress, Association> byAddress = new HashMap<>();
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    private final AtomicLongArray dtlsCounts = new AtomicLongArray(Counter.values().length);
    private final MessageHandler replyHandler = this::onReply;
    private final MessageHandler coaHandler = this::onCoa;
    private final java.util.concurrent.atomic.AtomicIntegerArray connectedNas;
    private final ByteBuffer reply = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final ByteBuffer empty = ByteBuffer.allocate(0);

    private ServerSocketChannel server;
    private DatagramChannel dtls;
    private ByteBuffer datagramIn;
    private ByteBuffer datagramOut;
    private Selector selector;
    private volatile int open;
    private volatile int openAssociations;
    private volatile boolean bound;
    private long now;
    private long nextHousekeeping;

    /**
     * @param clientIndex the index in {@link RadsecLink#clients} of each NAS entry allowed over RadSec, by name
     * @param dtlsIndex the same for the NAS entries allowed over DTLS
     * @param auth whether Access-Requests are answered (otherwise only accounting)
     */
    RadsecAgent(
            RadsecConfig config,
            NasRegistry registry,
            RadsecLink link,
            Map<String, Integer> clientIndex,
            Map<String, Integer> dtlsIndex,
            boolean auth,
            UdpAgent.NanoClock clock) {
        this.config = config;
        this.registry = registry;
        this.link = link;
        this.clientIndex = Map.copyOf(clientIndex);
        this.dtlsIndex = Map.copyOf(dtlsIndex);
        this.auth = auth;
        this.clock = clock;
        this.certificateOnly = registry.clients().stream()
                .filter(NasClient::certificateOnly)
                .filter(n -> config.clients().containsKey(n.name()))
                .sorted(java.util.Comparator.comparing(NasClient::name))
                .toList();
        this.dtlsCertificateOnly = registry.clients().stream()
                .filter(NasClient::certificateOnly)
                .filter(n -> config.dtls().clients().containsKey(n.name()))
                .sorted(java.util.Comparator.comparing(NasClient::name))
                .toList();
        this.connectedNas = new java.util.concurrent.atomic.AtomicIntegerArray(Math.max(1, link.clients.length));
        this.connections = new Connection[config.connections()];
        this.generations = new int[config.connections()];
        this.associations =
                new Association[config.dtls().enabled() ? config.dtls().associations() : 0];
        this.dtlsGenerations = new int[associations.length];
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

    /** One DTLS association: a NAS address and port, its engine, and the plaintext of the record being read. */
    private static final class Association {
        final int index;
        final int generation;
        final SSLEngine engine;
        final InetSocketAddress remote;
        final long openedAt;
        final long startedAt = System.currentTimeMillis(); // to compare with the TLS session's creation time
        final ByteBuffer appIn;
        final UnsafeBuffer appView;
        long lastActivity;
        long nextRetransmit;
        long retransmitInterval;
        int nas = -1;

        Association(int index, int generation, SSLEngine engine, InetSocketAddress remote, long now, long retransmit) {
            this.index = index;
            this.generation = generation;
            this.engine = engine;
            this.remote = remote;
            this.openedAt = now;
            this.lastActivity = now;
            this.retransmitInterval = retransmit;
            this.nextRetransmit = now + retransmit;
            appIn = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() + RadiusPacket.MAX_LENGTH);
            appView = new UnsafeBuffer(appIn);
        }
    }

    /** The route of an association: its slot after the TCP connections. */
    private long route(Association a) {
        return RadsecLink.route(connections.length + a.index, a.generation);
    }

    @Override
    public void onStart() {
        String where = config.host() + ":" + config.port();
        try {
            selector = Selector.open();
            if (config.tcp()) {
                server = ServerSocketChannel.open();
                server.bind(new InetSocketAddress(config.host(), config.port()), 128);
                server.configureBlocking(false);
                server.register(selector, SelectionKey.OP_ACCEPT);
                LOG.info("listening for RadSec on {}", server.getLocalAddress());
            }
            if (config.dtls().enabled()) {
                where = config.host() + ":" + config.dtls().port() + "/udp";
                dtls = DatagramChannel.open();
                dtls.bind(new InetSocketAddress(config.host(), config.dtls().port()));
                dtls.configureBlocking(false);
                dtls.register(selector, SelectionKey.OP_READ);
                datagramIn = ByteBuffer.allocate(1 << 16);
                datagramOut = ByteBuffer.allocate(1 << 16);
                LOG.info("listening for RADIUS over DTLS on {}", dtls.getLocalAddress());
            }
            bound = true;
        } catch (IOException e) {
            throw new IllegalStateException("cannot bind RadSec socket " + where, e);
        }
    }

    /** Port actually bound (useful when configured as 0); -1 without the TCP listener. */
    int localPort() {
        try {
            return server == null ? -1 : ((InetSocketAddress) server.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    /** DTLS port actually bound; -1 without DTLS. */
    int localDtlsPort() {
        try {
            return dtls == null ? -1 : ((InetSocketAddress) dtls.getLocalAddress()).getPort();
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
                } else if (key.channel() == dtls) {
                    receive();
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
        c.nas = nasOf(c.engine, c.remote, config.clients(), clientIndex, certificateOnly, "RadSec", counts);
        connectedNas.incrementAndGet(c.nas);
        if (c.engine.getSession().getCreationTime() < c.acceptedAt) {
            increment(Counter.HANDSHAKES_RESUMED); // a session from an earlier connection
        }
    }

    /**
     * The link index of the NAS entry a peer belongs to: the entry of its address if that allows the transport (and its
     * certificate carries the entry's identity, if one is set), else a certificate-only entry its certificate names.
     */
    private int nasOf(
            SSLEngine engine,
            InetSocketAddress remote,
            Map<String, RadsecConfig.Client> clients,
            Map<String, Integer> indexes,
            List<NasClient> byCertificate,
            String transport,
            AtomicLongArray counters)
            throws Refused {
        X509Certificate certificate = peerCertificate(engine);
        NasClient nas = registry.lookup(remote.getAddress());
        Integer index = nas == null ? null : indexes.get(nas.name());
        RadsecConfig.Client client = index == null ? null : clients.get(nas.name());
        if (client == null && certificate != null) { // no entry for the address allows it: by certificate alone
            for (NasClient candidate : byCertificate) {
                if (CertificateIdentity.matches(
                        certificate, clients.get(candidate.name()).identity())) {
                    nas = candidate;
                    index = indexes.get(candidate.name());
                    client = clients.get(candidate.name());
                    break;
                }
            }
        }
        if (certificate == null
                || client == null
                || (client.identity() != null && !CertificateIdentity.matches(certificate, client.identity()))) {
            counters.incrementAndGet(Counter.NAS_REFUSED.ordinal());
            LOG.info(
                    "{} connection from {} refused: {}",
                    transport,
                    remote,
                    nas == null
                            ? "no NAS entry for the address"
                            : client == null
                                    ? "NAS entry " + nas.name() + " does not allow " + transport
                                    : "certificate " + certificate.getSubjectX500Principal() + " does not name "
                                            + client.identity());
            throw new Refused();
        }
        LOG.info("{} connection from {} for NAS {}", transport, remote, nas.name());
        return index;
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
                forward(c.route(), c.nas, c.appView, in.get(at) & 0xFF, at, length, counts);
                in.position(at + length);
            }
        } finally {
            in.compact();
        }
    }

    private void forward(
            long route, int nas, UnsafeBuffer packet, int code, int offset, int length, AtomicLongArray counters) {
        if (code == DynamicAuthorization.DISCONNECT_ACK
                || code == DynamicAuthorization.DISCONNECT_NAK
                || code == DynamicAuthorization.COA_ACK
                || code == DynamicAuthorization.COA_NAK) {
            int index = link.fromNas.tryClaim(RadsecLink.PACKET_MSG, 4 + length);
            if (index > 0) {
                link.fromNas.buffer().putInt(index, nas);
                link.fromNas.buffer().putBytes(index + 4, packet, offset, length);
                link.fromNas.commit(index);
                counters.incrementAndGet(Counter.COA_ANSWERS.ordinal());
            } else {
                counters.incrementAndGet(Counter.DROPPED.ordinal());
            }
            return;
        }
        counters.incrementAndGet(Counter.REQUESTS.ordinal());
        org.agrona.concurrent.ringbuffer.RingBuffer ring = switch (code) {
            case RadiusCode.ACCESS_REQUEST -> auth ? link.toAuth : null;
            case RadiusCode.ACCOUNTING_REQUEST -> link.toAccounting;
            case RadiusCode.STATUS_SERVER -> auth ? link.toAuth : link.toAccounting;
            default -> null;
        };
        if (ring == null) {
            counters.incrementAndGet(Counter.NOT_HANDLED.ordinal());
        } else if (!RadsecLink.request(ring, route, nas, packet, offset, length)) {
            counters.incrementAndGet(Counter.DROPPED.ordinal());
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
        for (Association a : associations) {
            if (a != null && a.nas == nas) {
                reply.clear();
                buffer.getBytes(index + 4, reply, length - 4);
                reply.flip();
                try {
                    send(a, reply);
                    dtlsCounts.incrementAndGet(Counter.COA_SENT.ordinal());
                } catch (IOException e) {
                    close(a);
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
        if (slot >= connections.length) {
            onDtlsReply(slot - connections.length, RadsecLink.generation(route), buffer, index, length);
            return;
        }
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

    // ---- DTLS (RFC 7360) ----

    /** The datagrams waiting on the DTLS socket, a bounded number per call. */
    private void receive() throws IOException {
        for (int n = 0; n < 64; n++) {
            datagramIn.clear();
            InetSocketAddress from = (InetSocketAddress) dtls.receive(datagramIn);
            if (from == null) {
                return;
            }
            datagramIn.flip();
            Association a = byAddress.get(from);
            try {
                if (a != null && a.nas >= 0 && clientHello(datagramIn)) {
                    dtlsCounts.incrementAndGet(Counter.RESTARTED.ordinal()); // RFC 6347 §4.2.8
                    close(a);
                    a = null;
                }
                if (a == null) {
                    a = associate(from);
                    if (a == null) {
                        continue;
                    }
                }
                a.lastActivity = now;
                progress(a, datagramIn);
            } catch (IOException | RuntimeException e) {
                if (a == null) {
                    LOG.debug("DTLS ClientHello from {} not taken: {}", from, e.toString());
                    continue;
                }
                if (a.nas < 0 && !(e instanceof Refused)) {
                    dtlsCounts.incrementAndGet(Counter.HANDSHAKES_FAILED.ordinal());
                    LOG.debug("DTLS handshake with {} failed: {}", from, e.getMessage());
                }
                close(a);
            }
        }
    }

    /**
     * A new association for a ClientHello from an address that a NAS entry allows over DTLS (or any, while entries
     * are identified by certificate alone); {@code null} when the datagram is dropped.
     */
    private Association associate(InetSocketAddress from) throws IOException {
        if (!clientHello(datagramIn)) {
            dtlsCounts.incrementAndGet(Counter.NOT_ASSOCIATED.ordinal());
            return null;
        }
        NasClient nas = registry.lookup(from.getAddress());
        if ((nas == null || !dtlsIndex.containsKey(nas.name())) && dtlsCertificateOnly.isEmpty()) {
            dtlsCounts.incrementAndGet(Counter.NAS_REFUSED.ordinal()); // no state for strangers
            return null;
        }
        int index = -1;
        for (int i = 0; i < associations.length && index < 0; i++) {
            if (associations[i] == null) {
                index = i;
            }
        }
        if (index < 0) {
            dtlsCounts.incrementAndGet(Counter.CONNECTIONS_REFUSED.ordinal());
            return null;
        }
        SSLEngine engine = config.credentials().currentDtls().createSSLEngine(from.getHostString(), from.getPort());
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);
        engine.setEnabledProtocols(new String[] {"DTLSv1.2"});
        Association a = new Association(
                index,
                dtlsGenerations[index],
                engine,
                from,
                now,
                config.dtls().retransmit().toNanos());
        engine.beginHandshake();
        associations[index] = a;
        byAddress.put(from, a);
        openAssociations++;
        dtlsCounts.incrementAndGet(Counter.CONNECTIONS_ACCEPTED.ordinal());
        return a;
    }

    /**
     * A DTLS handshake record carrying a ClientHello in epoch 0: content type 22, version 254.x, epoch 0, and handshake
     * type 1 after the 13-byte record header.
     */
    static boolean clientHello(ByteBuffer d) {
        int at = d.position();
        return d.remaining() >= 14
                && d.get(at) == 22
                && (d.get(at + 1) & 0xFF) == 0xFE
                && d.get(at + 3) == 0
                && d.get(at + 4) == 0
                && d.get(at + 13) == 1;
    }

    /** Drives an association's engine over one datagram: handshake steps, then each record's RADIUS packet. */
    private void progress(Association a, ByteBuffer in) throws IOException {
        while (true) {
            SSLEngineResult.HandshakeStatus hs = a.engine.getHandshakeStatus();
            if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task = a.engine.getDelegatedTask()) != null) {
                    task.run();
                }
                continue;
            }
            if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(a, empty);
                continue;
            }
            if (!in.hasRemaining() && hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                return;
            }
            a.appIn.clear();
            SSLEngineResult r = a.engine.unwrap(in, a.appIn);
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                close(a);
                return;
            }
            if (r.getStatus() != SSLEngineResult.Status.OK) {
                return; // a record that does not fit: dropped, as a datagram may be
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                established(a);
            }
            if (r.bytesProduced() > 0) {
                record(a, r.bytesProduced());
            } else if (r.bytesConsumed() == 0
                    && r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                return; // nothing more to make of this datagram
            }
        }
    }

    /** One decrypted record: a whole RADIUS packet, else silently discarded (RFC 7360 §3: as over UDP). */
    private void record(Association a, int length) {
        if (a.nas < 0) {
            return;
        }
        int declared = length >= 4 ? a.appView.getShort(2, java.nio.ByteOrder.BIG_ENDIAN) & 0xFFFF : -1;
        if (declared < RadiusPacket.HEADER_LENGTH || declared > length) {
            dtlsCounts.incrementAndGet(Counter.MALFORMED.ordinal());
            return;
        }
        a.lastActivity = now;
        forward(route(a), a.nas, a.appView, a.appView.getByte(0) & 0xFF, 0, declared, dtlsCounts);
    }

    private void established(Association a) throws IOException {
        if (a.nas >= 0) {
            return;
        }
        a.nas = nasOf(a.engine, a.remote, config.dtls().clients(), dtlsIndex, dtlsCertificateOnly, "DTLS", dtlsCounts);
        connectedNas.incrementAndGet(a.nas);
        if (a.engine.getSession().getCreationTime() < a.startedAt) {
            dtlsCounts.incrementAndGet(Counter.HANDSHAKES_RESUMED.ordinal());
        }
    }

    /** Encrypts {@code plain} or the next handshake record, and sends each datagram the engine makes. */
    private void wrap(Association a, ByteBuffer plain) throws IOException {
        do {
            datagramOut.clear();
            SSLEngineResult r = a.engine.wrap(plain, datagramOut);
            datagramOut.flip();
            if (datagramOut.hasRemaining()) {
                dtls.send(datagramOut, a.remote); // a full socket buffer drops it: the peer retransmits
            }
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("DTLS closed"); // after sending the close_notify the engine made
            }
            if (r.getStatus() != SSLEngineResult.Status.OK) {
                throw new SSLException("DTLS record does not fit: " + r.getStatus());
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
                established(a);
            }
        } while (plain.hasRemaining());
    }

    /** A RADIUS packet to the NAS of an association, in one record. */
    private void send(Association a, ByteBuffer packet) throws IOException {
        wrap(a, packet);
    }

    /** The handshake flight again, the timer doubled up to 8 times its first value (RFC 6347 §4.2.4.1). */
    private void retransmit(Association a) {
        long first = config.dtls().retransmit().toNanos();
        a.retransmitInterval = Math.min(a.retransmitInterval * 2, first * 8);
        a.nextRetransmit = now + a.retransmitInterval;
        dtlsCounts.incrementAndGet(Counter.RETRANSMISSIONS.ordinal());
        try {
            do {
                wrap(a, empty); // the JDK sends its last flight again when wrapping while it waits for the peer
                SSLEngineResult.HandshakeStatus hs = a.engine.getHandshakeStatus();
                if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    Runnable task;
                    while ((task = a.engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                }
            } while (a.engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP);
        } catch (IOException | RuntimeException e) {
            close(a);
        }
    }

    private void onDtlsReply(int slot, int generation, DirectBuffer buffer, int index, int length) {
        Association a = slot < associations.length ? associations[slot] : null;
        if (a == null || a.generation != generation || a.nas < 0) {
            dtlsCounts.incrementAndGet(Counter.REPLIES_STALE.ordinal());
            return;
        }
        reply.clear();
        buffer.getBytes(index + 8, reply, length - 8);
        reply.flip();
        try {
            send(a, reply);
            dtlsCounts.incrementAndGet(Counter.REPLIES.ordinal());
        } catch (IOException e) {
            close(a);
        }
    }

    private void close(Association a) {
        if (associations[a.index] != a) {
            return;
        }
        associations[a.index] = null;
        byAddress.remove(a.remote, a);
        if (a.nas >= 0) {
            connectedNas.decrementAndGet(a.nas);
        }
        dtlsGenerations[a.index] = (a.generation + 1) & 0x7FFF_FFFF;
        openAssociations--;
        dtlsCounts.incrementAndGet(Counter.CONNECTIONS_CLOSED.ordinal());
        try {
            a.engine.closeOutbound();
            datagramOut.clear();
            a.engine.wrap(empty, datagramOut); // close_notify, best effort
            datagramOut.flip();
            if (datagramOut.hasRemaining()) {
                dtls.send(datagramOut, a.remote);
            }
        } catch (IOException | RuntimeException e) {
            // closing anyway
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
        long dtlsIdle = config.dtls().idleTimeout().toNanos();
        for (Association a : associations) {
            if (a == null) {
                continue;
            }
            if ((a.nas < 0 && now - a.openedAt > handshake) || (dtlsIdle > 0 && now - a.lastActivity > dtlsIdle)) {
                dtlsCounts.incrementAndGet(Counter.TIMED_OUT.ordinal());
                close(a);
            } else if (now - a.nextRetransmit >= 0 && a.engine.getHandshakeStatus() != NOT_HANDSHAKING) {
                retransmit(a);
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

    long getDtls(Counter counter) {
        return dtlsCounts.get(counter.ordinal());
    }

    int openAssociations() {
        return openAssociations;
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
        if (dtls != null) {
            w.counter("radiusward_gateway_dtls_total", "DTLS associations and packets by what happened to them");
            for (Counter c : Counter.values()) {
                w.sample(getDtls(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
            }
            w.gauge("radiusward_gateway_dtls_associations", "Open DTLS associations")
                    .sample(openAssociations, "gateway", gateway);
        }
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
        for (Association a : associations) {
            if (a != null) {
                close(a);
            }
        }
        try {
            if (server != null) {
                server.close();
            }
            if (dtls != null) {
                dtls.close();
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
