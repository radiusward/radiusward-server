/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import org.agrona.BufferUtil;
import org.agrona.concurrent.Agent;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Owns the Access-Request socket (Phase 5): a non-blocking NIO {@link DatagramChannel} on one thread, like the
 * accounting {@link UdpAgent}. Per datagram: validate → NAS entry → Message-Authenticator (required by default and
 * with EAP) → reply cache (RFC 5080: a retransmission is answered with the same reply, or dropped while its original
 * is still being decided) → copy into a free {@link AccessSlots slot} and queue it for the {@link AccessWorker}s.
 * Replies come back through the done queue and leave from this socket. Never blocks and allocates nothing per
 * packet except the sender address the JDK creates: no free slot or a full queue means the request is dropped and
 * the NAS retransmits.
 */
final class AuthAgent implements Agent {

    private static final Logger LOG = LogManager.getLogger(AuthAgent.class);
    private static final int RECEIVE_BATCH = 64;

    private final GatewayConfig gateway;
    private final AuthConfig config;
    private final NasRegistry registry;
    private final AccessSlots slots;
    private final AuthStats stats;
    private final UdpAgent.NanoClock clock;
    private final long ttlNanos;

    private final ByteBuffer receiveBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH + 64, 64);
    private final UnsafeBuffer received = new UnsafeBuffer(receiveBuffer);
    private final ByteBuffer sendBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer sending = new UnsafeBuffer(sendBuffer);
    private final RadiusPacket packet = new RadiusPacket();
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final io.radiusward.radius.codec.AccessResponses statusResponses =
            new io.radiusward.radius.codec.AccessResponses(new RadiusAuthenticator());
    private final ReplyCache cache;

    private DatagramChannel channel;
    private long now;

    AuthAgent(
            GatewayConfig gateway,
            AuthConfig config,
            NasRegistry registry,
            AccessSlots slots,
            AuthStats stats,
            UdpAgent.NanoClock clock) {
        this.gateway = gateway;
        this.config = config;
        this.registry = registry;
        this.slots = slots;
        this.stats = stats;
        this.clock = clock;
        this.ttlNanos = config.replyCacheTtl().toNanos();
        this.cache = new ReplyCache(config.replyCacheEntries());
    }

    @Override
    public void onStart() {
        try {
            channel = DatagramChannel.open();
            channel.setOption(StandardSocketOptions.SO_RCVBUF, gateway.socketReceiveBuffer());
            channel.bind(new InetSocketAddress(gateway.listenHost(), config.port()));
            channel.configureBlocking(false);
            stats.bound(true);
            LOG.info("listening for RADIUS Access-Requests on {}", channel.getLocalAddress());
        } catch (IOException e) {
            throw new IllegalStateException(
                    "cannot bind RADIUS authentication socket " + gateway.listenHost() + ":" + config.port(), e);
        }
    }

    /** Port actually bound (useful when configured as 0). */
    int localPort() {
        try {
            return ((InetSocketAddress) channel.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    @Override
    public int doWork() throws IOException {
        now = clock.nanoTime();
        int work = 0;
        for (int i = 0; i < RECEIVE_BATCH; i++) {
            receiveBuffer.clear();
            SocketAddress from = channel.receive(receiveBuffer);
            if (from == null) {
                break;
            }
            onDatagram((InetSocketAddress) from, receiveBuffer.position());
            work++;
        }
        for (Integer id = slots.done.poll(); id != null; id = slots.done.poll()) {
            reply(id);
            work++;
        }
        stats.inFlight(slots.inUse());
        stats.cached(cache.size());
        return work;
    }

    private void onDatagram(InetSocketAddress from, int length) {
        stats.increment(AuthStats.Counter.RECEIVED);
        if (packet.wrap(received, 0, length) != DecodeStatus.OK) {
            stats.increment(AuthStats.Counter.MALFORMED);
            return;
        }
        if (packet.code() == RadiusCode.STATUS_SERVER) {
            statusServer(from);
            return;
        }
        if (packet.code() != RadiusCode.ACCESS_REQUEST) {
            stats.increment(AuthStats.Counter.NOT_ACCESS_REQUEST);
            return;
        }
        NasClient nas = registry.lookup(from.getAddress());
        if (nas == null) {
            stats.increment(AuthStats.Counter.UNKNOWN_NAS);
            return;
        }
        boolean hasMa = packet.hasMessageAuthenticator();
        NasClient.MessageAuthenticatorPolicy policy = nas.accessMessageAuthenticator();
        boolean required = policy == NasClient.MessageAuthenticatorPolicy.REQUIRED
                || packet.findAttribute(AccessRequests.EAP_MESSAGE) >= 0; // RFC 3579 §3.2
        if (!hasMa && required) {
            stats.increment(AuthStats.Counter.MESSAGE_AUTHENTICATOR_MISSING);
            return;
        }
        if (hasMa
                && (policy != NasClient.MessageAuthenticatorPolicy.OFF || required)
                && !authenticator.verifyRequestMessageAuthenticator(packet, nas.secret())) {
            stats.increment(AuthStats.Counter.MESSAGE_AUTHENTICATOR_FAILED);
            return;
        }

        int auth = packet.authenticatorOffset();
        long key = ResponseCache.key(
                from.getAddress().hashCode(),
                from.getPort(),
                packet.identifier(),
                received.getLong(auth),
                received.getLong(auth + 8));
        int cached = cache.lookup(key, now);
        if (cached == ReplyCache.IN_FLIGHT) {
            stats.increment(AuthStats.Counter.RETRANSMIT_IN_FLIGHT);
            return;
        }
        if (cached >= 0) {
            stats.increment(AuthStats.Counter.CACHE_HITS);
            int replyLength = cache.copy(cached, sending, 0);
            send(sendBuffer, replyLength, from);
            return;
        }

        int slot = slots.allocate();
        if (slot < 0) {
            stats.increment(AuthStats.Counter.BUSY);
            return;
        }
        slots.requests.putBytes(AccessSlots.requestOffset(slot), received, 0, packet.length());
        slots.requestLength[slot] = packet.length();
        slots.source[slot] = from;
        slots.nas[slot] = nas;
        slots.cacheKey[slot] = key;
        if (!slots.work.offer(slots.ids[slot])) {
            slots.release(slot);
            stats.increment(AuthStats.Counter.BUSY);
            return;
        }
        cache.markInFlight(key);
    }

    private void reply(int slot) {
        int length = slots.replyLength[slot];
        long key = slots.cacheKey[slot];
        if (length > 0) {
            send(slots.replies[slot], length, slots.source[slot]);
            cache.put(key, slots.replyViews[slot], 0, length, now + ttlNanos);
        } else {
            cache.clearInFlight(key); // not answered: a retransmission is decided again
        }
        slots.release(slot);
    }

    /**
     * Status-Server on the authentication port (RFC 5997): an Access-Accept without attributes when a valid
     * Message-Authenticator proves the NAS; otherwise silence. Answered on this thread, never cached.
     */
    private void statusServer(InetSocketAddress from) {
        NasClient nas = registry.lookup(from.getAddress());
        if (nas == null) {
            stats.increment(AuthStats.Counter.UNKNOWN_NAS);
            return;
        }
        if (!packet.hasMessageAuthenticator()) {
            stats.increment(AuthStats.Counter.MESSAGE_AUTHENTICATOR_MISSING);
            return;
        }
        if (!authenticator.verifyRequestMessageAuthenticator(packet, nas.secret())) {
            stats.increment(AuthStats.Counter.MESSAGE_AUTHENTICATOR_FAILED);
            return;
        }
        stats.increment(AuthStats.Counter.STATUS_SERVER);
        int length = statusResponses.encode(packet, RadiusCode.ACCESS_ACCEPT, received, 0, 0, sending, 0, nas.secret());
        send(sendBuffer, length, from);
    }

    private void send(ByteBuffer buffer, int length, InetSocketAddress to) {
        buffer.clear().limit(length);
        try {
            if (channel.send(buffer, to) == length) {
                stats.increment(AuthStats.Counter.RESPONSES_SENT);
            } else {
                stats.increment(AuthStats.Counter.SEND_FAILED);
            }
        } catch (IOException e) {
            stats.increment(AuthStats.Counter.SEND_FAILED);
        }
    }

    @Override
    public void onClose() {
        stats.bound(false);
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            LOG.warn("closing the authentication socket: {}", e.toString());
        }
    }

    @Override
    public String roleName() {
        return "auth-agent";
    }
}
