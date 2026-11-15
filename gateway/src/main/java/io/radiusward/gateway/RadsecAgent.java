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
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLongArray;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
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
 * <p>RADIUS over DTLS 1.2 (RFC 7360, ADR 0038) on a UDP socket of the same selector: {@link DtlsServer}, whose
 * associations take the route slots after the TCP connections. What both transports do alike once a peer is connected
 * (its NAS entry, forwarding its packets) is {@link RadsecPeers}.
 *
 * <p>RADIUS over plain TCP (RFC 6613, ADR 0045) on two more listeners of the same selector, authentication and
 * accounting: connections without TLS, bound to the NAS entry of their address when accepted (it must allow TCP),
 * signed with the entry's own secret; a packet of the other port's kind is discarded.
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
    private final Map<String, Integer> tcpIndex;
    private final boolean auth;
    private final UdpAgent.NanoClock clock;
    private final List<NasClient> certificateOnly;
    private final Connection[] connections;
    private final int[] generations;
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    private final AtomicLongArray tcpCounts = new AtomicLongArray(Counter.values().length);
    private final MessageHandler replyHandler = this::onReply;
    private final MessageHandler coaHandler = this::onCoa;
    private final java.util.concurrent.atomic.AtomicIntegerArray connectedNas;
    private final ByteBuffer reply = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final ByteBuffer empty = ByteBuffer.allocate(0);

    private ServerSocketChannel server;
    private ServerSocketChannel tcpAuth;
    private ServerSocketChannel tcpAccounting;
    private final RadsecPeers peers;
    private final DtlsServer dtls; // null without DTLS
    private Selector selector;
    private final java.util.concurrent.atomic.AtomicInteger open = new java.util.concurrent.atomic.AtomicInteger();
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
            Map<String, Integer> tcpIndex,
            boolean auth,
            UdpAgent.NanoClock clock) {
        this.config = config;
        this.registry = registry;
        this.link = link;
        this.clientIndex = Map.copyOf(clientIndex);
        this.tcpIndex = Map.copyOf(tcpIndex);
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
        this.peers = new RadsecPeers(registry, link, auth);
        this.dtls = config.dtls().enabled()
                ? new DtlsServer(config, registry, peers, dtlsIndex, connectedNas, config.connections())
                : null;
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
        /** Plain TCP (no engine): {@link #AUTH_PORT} or {@link #ACCOUNTING_PORT}; 0 for TLS. */
        final int port;

        Connection(int index, int generation, SocketChannel channel, SSLEngine engine, long now) throws IOException {
            this(index, generation, channel, engine, now, 0);
        }

        Connection(int index, int generation, SocketChannel channel, SSLEngine engine, long now, int port)
                throws IOException {
            this.index = index;
            this.generation = generation;
            this.channel = channel;
            this.engine = engine;
            this.port = port;
            this.remote = (InetSocketAddress) channel.getRemoteAddress();
            this.openedAt = now;
            this.lastActivity = now;
            int packetSize = engine == null
                    ? RadiusPacket.MAX_LENGTH
                    : engine.getSession().getPacketBufferSize();
            netIn = ByteBuffer.allocate(packetSize);
            appIn = ByteBuffer.allocate((engine == null
                            ? RadiusPacket.MAX_LENGTH
                            : engine.getSession().getApplicationBufferSize())
                    + RadiusPacket.MAX_LENGTH);
            appView = new UnsafeBuffer(appIn);
            netOut = ByteBuffer.allocate(packetSize * 2);
        }

        AtomicLongArray counters(RadsecAgent agent) {
            return engine == null ? agent.tcpCounts : agent.counts;
        }

        long route() {
            return RadsecLink.route(index, generation);
        }
    }

    static final int AUTH_PORT = 1;
    static final int ACCOUNTING_PORT = 2;

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
            if (config.plain().enabled()) {
                where = config.host() + ":" + config.plain().authPort() + "/tcp";
                tcpAuth = ServerSocketChannel.open();
                tcpAuth.bind(new InetSocketAddress(config.host(), config.plain().authPort()), 128);
                tcpAuth.configureBlocking(false);
                tcpAuth.register(selector, SelectionKey.OP_ACCEPT, AUTH_PORT);
                where = config.host() + ":" + config.plain().accountingPort() + "/tcp";
                tcpAccounting = ServerSocketChannel.open();
                tcpAccounting.bind(
                        new InetSocketAddress(config.host(), config.plain().accountingPort()), 128);
                tcpAccounting.configureBlocking(false);
                tcpAccounting.register(selector, SelectionKey.OP_ACCEPT, ACCOUNTING_PORT);
                LOG.info(
                        "listening for RADIUS over TCP on {} (authentication) and {} (accounting)",
                        tcpAuth.getLocalAddress(),
                        tcpAccounting.getLocalAddress());
            }
            if (dtls != null) {
                where = config.host() + ":" + config.dtls().port() + "/udp";
                dtls.open(selector);
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

    /** The plain TCP authentication ({@code true}) or accounting port actually bound; -1 without plain TCP. */
    int localTcpPort(boolean authentication) {
        ServerSocketChannel s = authentication ? tcpAuth : tcpAccounting;
        try {
            return s == null ? -1 : ((InetSocketAddress) s.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    /** DTLS port actually bound; -1 without DTLS. */
    int localDtlsPort() {
        return dtls == null ? -1 : dtls.localPort();
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
                if (key.isAcceptable() && key.attachment() instanceof Integer port) {
                    acceptPlain((ServerSocketChannel) key.channel(), port);
                } else if (key.isAcceptable()) {
                    accept();
                } else if (key.attachment() instanceof DtlsServer d) {
                    d.receive(now);
                } else if (key.attachment() instanceof Connection c) {
                    try {
                        if (key.isReadable()) {
                            read(c);
                        }
                        if (key.isValid() && key.isWritable()) {
                            flush(c);
                        }
                    } catch (IOException e) {
                        if (c.nas < 0 && !(e instanceof RadsecPeers.Refused)) {
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
            open.incrementAndGet();
            increment(Counter.CONNECTIONS_ACCEPTED);
        }
    }

    /** A plain TCP connection: bound to the NAS entry of its address at once, which must allow TCP. */
    private void acceptPlain(ServerSocketChannel listener, int port) throws IOException {
        SocketChannel channel;
        while ((channel = listener.accept()) != null) {
            InetSocketAddress remote = (InetSocketAddress) channel.getRemoteAddress();
            NasClient nas = registry.lookup(remote.getAddress());
            Integer nasIndex = nas == null ? null : tcpIndex.get(nas.name());
            int index = freeIndex();
            if (nasIndex == null || index < 0) {
                tcpCounts.incrementAndGet(
                        (nasIndex == null ? Counter.NAS_REFUSED : Counter.CONNECTIONS_REFUSED).ordinal());
                channel.close();
                continue;
            }
            channel.configureBlocking(false);
            channel.setOption(StandardSocketOptions.TCP_NODELAY, true);
            channel.setOption(StandardSocketOptions.SO_KEEPALIVE, true);
            Connection c = new Connection(index, generations[index], channel, null, now, port);
            c.nas = nasIndex;
            c.key = channel.register(selector, SelectionKey.OP_READ, c);
            connections[index] = c;
            open.incrementAndGet();
            tcpCounts.incrementAndGet(Counter.CONNECTIONS_ACCEPTED.ordinal());
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
        if (c.engine == null) {
            if (c.channel.read(c.appIn) < 0) {
                close(c);
                return;
            }
            c.lastActivity = now;
            dispatch(c);
            if (connections[c.index] == c) {
                flush(c);
            }
            return;
        }
        if (!c.netIn.hasRemaining()) {
            c.netIn = SslEngines.grow(c.netIn, c.engine.getSession().getPacketBufferSize());
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
                SslEngines.runTasks(c.engine); // certificate checks; OCSP may wait for its timeout (ADR 0033)
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

    /** Encrypts {@code plain} (or a handshake message) into the connection's output; plain TCP copies it. */
    private void wrap(Connection c, ByteBuffer plain) throws IOException {
        if (c.engine == null) {
            if (c.netOut.remaining() < plain.remaining()) {
                if (c.netOut.capacity() + plain.remaining() > MAX_PENDING_OUTPUT) {
                    throw new IOException("peer does not read its replies");
                }
                c.netOut = SslEngines.grow(c.netOut, plain.remaining());
            }
            c.netOut.put(plain);
            return;
        }
        do {
            int need = c.engine.getSession().getPacketBufferSize();
            if (c.netOut.remaining() < need) {
                if (c.netOut.capacity() + need > MAX_PENDING_OUTPUT) {
                    throw new IOException("peer does not read its replies");
                }
                c.netOut = SslEngines.grow(c.netOut, need);
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

    /** The handshake is done: the connection belongs to the NAS entry of its address, if that allows RadSec. */
    private void established(Connection c) throws IOException {
        if (c.nas >= 0) {
            return;
        }
        c.nas = peers.nasOf(c.engine, c.remote, config.clients(), clientIndex, certificateOnly, "RadSec", counts);
        connectedNas.incrementAndGet(c.nas);
        if (c.engine.getSession().getCreationTime() < c.acceptedAt) {
            increment(Counter.HANDSHAKES_RESUMED); // a session from an earlier connection
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
                    c.counters(this).incrementAndGet(Counter.MALFORMED.ordinal());
                    throw new IOException("malformed RADIUS packet over TCP"); // RFC 6613 §2.6.4: close
                }
                if (in.remaining() < length) {
                    break;
                }
                int code = in.get(at) & 0xFF;
                if ((c.port == AUTH_PORT && code == RadiusCode.ACCOUNTING_REQUEST)
                        || (c.port == ACCOUNTING_PORT && code == RadiusCode.ACCESS_REQUEST)) {
                    c.counters(this).incrementAndGet(Counter.NOT_HANDLED.ordinal()); // the other port's kind
                } else {
                    peers.forward(
                            c.route(), c.nas, c.appView, code, at, length, c.counters(this), c.port == ACCOUNTING_PORT);
                }
                in.position(at + length);
            }
        } finally {
            in.compact();
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
        if (dtls != null && dtls.coa(nas, buffer, index + 4, length - 4)) {
            return;
        }
        increment(Counter.COA_NO_CONNECTION); // the request times out at the sender
    }

    /** A reply from a deciding agent: written to its connection if that is still the same one. */
    private void onReply(int msgTypeId, DirectBuffer buffer, int index, int length) {
        long route = buffer.getLong(index);
        int slot = RadsecLink.connection(route);
        if (slot >= connections.length) {
            if (dtls != null) {
                dtls.reply(slot - connections.length, RadsecLink.generation(route), buffer, index + 8, length - 8);
            } else {
                increment(Counter.REPLIES_STALE);
            }
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
            c.counters(this).incrementAndGet(Counter.REPLIES.ordinal()); // before the flush: the NAS may read it first
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
        if (dtls != null) {
            dtls.housekeeping(now, handshake);
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
        open.decrementAndGet();
        c.counters(this).incrementAndGet(Counter.CONNECTIONS_CLOSED.ordinal());
        try {
            if (c.engine == null) {
                throw new IOException("plain TCP: no close_notify");
            }
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

    long getTcp(Counter counter) {
        return tcpCounts.get(counter.ordinal());
    }

    long getDtls(Counter counter) {
        return dtls == null ? 0 : dtls.get(counter);
    }

    int openAssociations() {
        return dtls == null ? 0 : dtls.openAssociations();
    }

    boolean bound() {
        return bound;
    }

    int openConnections() {
        return open.get();
    }

    /** The server certificate of RadSec and DTLS; {@code null} without one. */
    TlsCredentials credentials() {
        return config.credentials();
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter("radiusward_gateway_radsec_total", "RadSec connections and packets by what happened to them");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
        }
        w.gauge("radiusward_gateway_radsec_connections", "Open RadSec connections")
                .sample(open.get(), "gateway", gateway);
        if (tcpAuth != null) {
            w.counter("radiusward_gateway_tcp_total", "Plain TCP connections and packets by what happened to them");
            for (Counter c : Counter.values()) {
                w.sample(getTcp(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
            }
        }
        if (dtls != null) {
            w.counter("radiusward_gateway_dtls_total", "DTLS associations and packets by what happened to them");
            for (Counter c : Counter.values()) {
                w.sample(getDtls(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
            }
            w.gauge("radiusward_gateway_dtls_associations", "Open DTLS associations")
                    .sample(dtls.openAssociations(), "gateway", gateway);
        }
        if (config.credentials() != null) {
            w.counter(
                    "radiusward_gateway_radsec_tls_reloads_total",
                    "Changes of the RadSec certificate, key, CA or CRL files: loaded, or failed (previous kept)");
            w.sample(config.credentials().reloads(), "gateway", gateway, "result", "loaded");
            w.sample(config.credentials().reloadFailures(), "gateway", gateway, "result", "failed");
        }
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
            if (tcpAuth != null) {
                tcpAuth.close();
                tcpAccounting.close();
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
