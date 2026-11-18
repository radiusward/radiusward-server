/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.server.RadsecAgent.Counter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicIntegerArray;
import java.util.concurrent.atomic.AtomicLongArray;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RADIUS over DTLS 1.2 (RFC 7360, ADR 0038), driven by the {@link RadsecAgent}'s thread and selector: one association
 * per NAS address and port, each with its {@link SSLEngine}, its NAS entry bound after the handshake as for TCP, one
 * RADIUS packet per record. Associations take the route slots after the TCP connections ({@code routeOffset}), so
 * replies and CoA requests find them the same way. Handshake flights are retransmitted on a doubling timer (RFC 6347
 * §4.2.4); a new ClientHello from the address of an established association replaces it (the NAS restarted, §4.2.8);
 * datagrams that are not DTLS, or not from an association or a ClientHello, are silently discarded.
 */
final class DtlsServer {

    private static final Logger LOG = LogManager.getLogger(RadsecAgent.class);

    private final RadsecConfig config;
    private final NasRegistry registry;
    private final RadsecPeers peers;
    private final Map<String, Integer> dtlsIndex;
    private final List<NasClient> certificateOnly;
    private final AtomicIntegerArray connectedNas;
    private final int routeOffset;
    private final Association[] associations;
    private final int[] generations;
    private final Map<InetSocketAddress, Association> byAddress = new HashMap<>();
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    private final ByteBuffer reply = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final ByteBuffer empty = ByteBuffer.allocate(0);

    private DatagramChannel channel;
    private ByteBuffer datagramIn;
    private ByteBuffer datagramOut;
    private final java.util.concurrent.atomic.AtomicInteger openCount = new java.util.concurrent.atomic.AtomicInteger();
    private long now;

    /**
     * @param dtlsIndex the index in {@link RadsecLink#clients} of each NAS entry allowed over DTLS, by name
     * @param connectedNas established peers per NAS index, shared with the TCP connections (CoA goes to any)
     * @param routeOffset the first route slot of the associations: the number of TCP connection slots
     */
    DtlsServer(
            RadsecConfig config,
            NasRegistry registry,
            RadsecPeers peers,
            Map<String, Integer> dtlsIndex,
            AtomicIntegerArray connectedNas,
            int routeOffset) {
        this.config = config;
        this.registry = registry;
        this.peers = peers;
        this.dtlsIndex = Map.copyOf(dtlsIndex);
        this.connectedNas = connectedNas;
        this.routeOffset = routeOffset;
        this.certificateOnly = registry.clients().stream()
                .filter(NasClient::certificateOnly)
                .filter(n -> config.dtls().clients().containsKey(n.name()))
                .sorted(java.util.Comparator.comparing(NasClient::name))
                .toList();
        this.associations = new Association[config.dtls().associations()];
        this.generations = new int[associations.length];
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

    /** Binds the UDP socket and registers it with the agent's selector. */
    void open(Selector selector) throws IOException {
        channel = DatagramChannel.open();
        channel.bind(new InetSocketAddress(config.host(), config.dtls().port()));
        channel.configureBlocking(false);
        channel.register(selector, SelectionKey.OP_READ, this);
        datagramIn = ByteBuffer.allocate(1 << 16);
        datagramOut = ByteBuffer.allocate(1 << 16);
        LOG.info("listening for RADIUS over DTLS on {}", channel.getLocalAddress());
    }

    /** Port actually bound; -1 before {@link #open}. */
    int localPort() {
        try {
            return channel == null ? -1 : ((InetSocketAddress) channel.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    /** The route of an association: its slot after the TCP connections. */
    private long route(Association a) {
        return RadsecLink.route(routeOffset + a.index, a.generation);
    }

    /** The datagrams waiting on the socket, a bounded number per call. */
    void receive(long time) throws IOException {
        now = time;
        for (int n = 0; n < 64; n++) {
            datagramIn.clear();
            InetSocketAddress from = (InetSocketAddress) channel.receive(datagramIn);
            if (from == null) {
                return;
            }
            datagramIn.flip();
            Association a = byAddress.get(from);
            try {
                if (a != null && a.nas >= 0 && clientHello(datagramIn)) {
                    counts.incrementAndGet(Counter.RESTARTED.ordinal()); // RFC 6347 §4.2.8
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
                if (a.nas < 0 && !(e instanceof RadsecPeers.Refused)) {
                    counts.incrementAndGet(Counter.HANDSHAKES_FAILED.ordinal());
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
            counts.incrementAndGet(Counter.NOT_ASSOCIATED.ordinal());
            return null;
        }
        NasClient nas = registry.lookup(from.getAddress());
        if ((nas == null || !dtlsIndex.containsKey(nas.name())) && certificateOnly.isEmpty()) {
            counts.incrementAndGet(Counter.NAS_REFUSED.ordinal()); // no state for strangers
            return null;
        }
        int index = -1;
        for (int i = 0; i < associations.length && index < 0; i++) {
            if (associations[i] == null) {
                index = i;
            }
        }
        if (index < 0) {
            counts.incrementAndGet(Counter.CONNECTIONS_REFUSED.ordinal());
            return null;
        }
        SSLEngine engine = config.credentials().currentDtls().createSSLEngine(from.getHostString(), from.getPort());
        engine.setUseClientMode(false);
        engine.setNeedClientAuth(true);
        engine.setEnabledProtocols(new String[] {"DTLSv1.2"});
        Association a = new Association(
                index,
                generations[index],
                engine,
                from,
                now,
                config.dtls().retransmit().toNanos());
        engine.beginHandshake();
        associations[index] = a;
        byAddress.put(from, a);
        openCount.incrementAndGet();
        counts.incrementAndGet(Counter.CONNECTIONS_ACCEPTED.ordinal());
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
                SslEngines.runTasks(a.engine);
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
            counts.incrementAndGet(Counter.MALFORMED.ordinal());
            return;
        }
        a.lastActivity = now;
        peers.forward(route(a), a.nas, a.appView, a.appView.getByte(0) & 0xFF, 0, declared, counts, false);
    }

    private void established(Association a) throws IOException {
        if (a.nas >= 0) {
            return;
        }
        a.nas = peers.nasOf(a.engine, a.remote, config.dtls().clients(), dtlsIndex, certificateOnly, "DTLS", counts);
        connectedNas.incrementAndGet(a.nas);
        if (a.engine.getSession().getCreationTime() < a.startedAt) {
            counts.incrementAndGet(Counter.HANDSHAKES_RESUMED.ordinal());
        }
    }

    /** Encrypts {@code plain} or the next handshake record, and sends each datagram the engine makes. */
    private void wrap(Association a, ByteBuffer plain) throws IOException {
        do {
            datagramOut.clear();
            SSLEngineResult r = a.engine.wrap(plain, datagramOut);
            datagramOut.flip();
            if (datagramOut.hasRemaining()) {
                channel.send(datagramOut, a.remote); // a full socket buffer drops it: the peer retransmits
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

    /** The handshake flight again, the timer doubled up to 8 times its first value (RFC 6347 §4.2.4.1). */
    private void retransmit(Association a) {
        long first = config.dtls().retransmit().toNanos();
        a.retransmitInterval = Math.min(a.retransmitInterval * 2, first * 8);
        a.nextRetransmit = now + a.retransmitInterval;
        counts.incrementAndGet(Counter.RETRANSMISSIONS.ordinal());
        try {
            do {
                wrap(a, empty); // the JDK sends its last flight again when wrapping while it waits for the peer
                SSLEngineResult.HandshakeStatus hs = a.engine.getHandshakeStatus();
                if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    SslEngines.runTasks(a.engine);
                }
            } while (a.engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP);
        } catch (IOException | RuntimeException e) {
            close(a);
        }
    }

    /**
     * A reply from a deciding agent for an association slot: sent if that association is still the same one.
     *
     * @param offset where the packet starts in {@code buffer}
     */
    void reply(int slot, int generation, DirectBuffer buffer, int offset, int length) {
        Association a = slot < associations.length ? associations[slot] : null;
        if (a == null || a.generation != generation || a.nas < 0) {
            counts.incrementAndGet(Counter.REPLIES_STALE.ordinal());
            return;
        }
        reply.clear();
        buffer.getBytes(offset, reply, length);
        reply.flip();
        counts.incrementAndGet(Counter.REPLIES.ordinal()); // before sending: the NAS may read it first
        try {
            wrap(a, reply);
        } catch (IOException e) {
            close(a);
        }
    }

    /**
     * A CoA or Disconnect-Request to the first established association of a NAS; {@code false} if it has none.
     *
     * @param offset where the packet starts in {@code buffer}
     */
    boolean coa(int nas, DirectBuffer buffer, int offset, int length) {
        for (Association a : associations) {
            if (a != null && a.nas == nas) {
                reply.clear();
                buffer.getBytes(offset, reply, length);
                reply.flip();
                try {
                    wrap(a, reply);
                    counts.incrementAndGet(Counter.COA_SENT.ordinal());
                } catch (IOException e) {
                    close(a);
                }
                return true;
            }
        }
        return false;
    }

    /** Handshakes that took too long, idle associations, and handshake flights due again. */
    void housekeeping(long time, long handshakeTimeout) {
        now = time;
        long idle = config.dtls().idleTimeout().toNanos();
        for (Association a : associations) {
            if (a == null) {
                continue;
            }
            if ((a.nas < 0 && now - a.openedAt > handshakeTimeout) || (idle > 0 && now - a.lastActivity > idle)) {
                counts.incrementAndGet(Counter.TIMED_OUT.ordinal());
                close(a);
            } else if (now - a.nextRetransmit >= 0 && a.engine.getHandshakeStatus() != NOT_HANDSHAKING) {
                retransmit(a);
            }
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
        generations[a.index] = (a.generation + 1) & 0x7FFF_FFFF;
        openCount.decrementAndGet();
        counts.incrementAndGet(Counter.CONNECTIONS_CLOSED.ordinal());
        try {
            a.engine.closeOutbound();
            datagramOut.clear();
            a.engine.wrap(empty, datagramOut); // close_notify, best effort
            datagramOut.flip();
            if (datagramOut.hasRemaining()) {
                channel.send(datagramOut, a.remote);
            }
        } catch (IOException | RuntimeException e) {
            // closing anyway
        }
    }

    long get(Counter counter) {
        return counts.get(counter.ordinal());
    }

    int openAssociations() {
        return openCount.get();
    }

    /** Closes every association (with a close_notify) and the socket. */
    void close() throws IOException {
        for (Association a : associations) {
            if (a != null) {
                close(a);
            }
        }
        if (channel != null) {
            channel.close();
        }
    }
}
