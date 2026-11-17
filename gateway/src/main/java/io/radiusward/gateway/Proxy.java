/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.radius.codec.attributes.Ietf.MESSAGE_AUTHENTICATOR;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.security.SecureRandom;
import java.util.List;
import org.agrona.BufferUtil;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends the Access-Requests of proxied realms to their home servers and their answers back to the NAS (ADR 0037).
 * Part of the {@link AuthAgent}'s thread: non-blocking, a preallocated table of requests in flight, nothing per packet
 * on the heap but what the JDK's socket hands over.
 *
 * <p>A request gets a new Request Authenticator and a Message-Authenticator for the home server's secret; its
 * User-Password is re-encrypted, a CHAP request without CHAP-Challenge gets the original authenticator as one, the
 * realm is stripped if configured, and a Proxy-State of ours is added. EAP passes through: the home server runs the
 * conversation, State and all. An answer counts only if it verifies (and carries a Message-Authenticator, unless
 * {@code proxy.require.message-authenticator = false}); our Proxy-State is removed, MS-MPPE keys and Tunnel-Password
 * are re-encrypted for the NAS's secret, and it is signed for the NAS like any reply. Unanswered requests are sent
 * again ({@code proxy.retries} every {@code proxy.timeout}), then dropped: the NAS asks again.
 *
 * <p>A home server that has answered nothing for {@code proxy.dead.after} while requests were waiting is dead: pools
 * skip it until it answers one of the Status-Server probes every server gets every {@code proxy.status.interval}.
 */
final class Proxy {

    private static final Logger LOG = LogManager.getLogger(Proxy.class);

    static final int NOT_PROXIED = 0;
    static final int TAKEN = 1;
    static final int DROPPED = 2;

    private static final int STATUS_ID = -2; // a home server's identifier used by its Status-Server probe

    /** Answers to the NAS go through the agent's own socket and reply cache. */
    interface Replies {
        void reply(ByteBuffer buffer, UnsafeBuffer view, int length, InetSocketAddress to, long route, long cacheKey);

        void drop(long cacheKey);
    }

    enum Counter {
        REQUESTS,
        ACCEPTED,
        REJECTED,
        CHALLENGED,
        RESENT,
        TIMEOUTS,
        INVALID
    }

    private final ProxyConfig config;
    private final Replies replies;
    private final boolean requireMessageAuthenticator;
    private final HomeServers homes;
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final SecureRandom random = new SecureRandom();
    private final RadiusPacket response = new RadiusPacket();

    // requests in flight
    private final int capacity;
    private final UnsafeBuffer packets;
    private final UnsafeBuffer ourAuthenticators;
    private final UnsafeBuffer nasAuthenticators;
    private final int[] home;
    private final int[] identifier;
    private final int[] nasIdentifier;
    private final int[] length;
    private final int[] sent;
    private final int[] generation;
    private final long[] deadline;
    private final long[] cacheKey;
    private final long[] route;
    private final InetSocketAddress[] from;
    private final NasClient[] nas;
    private final boolean[] inUse;
    private final ProxyConfig.Realm[] realmOfSlot; // for the answer's rewriting (ADR 0055)
    private final ProxyCodec codec;
    private final int[] free;
    private int freeCount;

    private final ByteBuffer receiveBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer received = new UnsafeBuffer(receiveBuffer);
    private final ByteBuffer replyBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer reply = new UnsafeBuffer(replyBuffer);
    private final ByteBuffer sendBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer sending = new UnsafeBuffer(sendBuffer);
    private final UnsafeBuffer statusAuth = new UnsafeBuffer(new byte[16]);
    private DatagramChannel channel;
    private java.nio.channels.Selector selector;
    private long nextTimeoutCheck;
    private long now;
    private HomeState reading; // the TLS home server whose packets are being read
    private final TlsClient.Packets tlsPackets = this::onTlsPacket;

    Proxy(ProxyConfig config, Replies replies, boolean requireMessageAuthenticator) {
        this(config, replies, requireMessageAuthenticator, null);
    }

    /** @param dictionary resolves the realms' rewrite rules (ADR 0055); {@code null}: none may be configured */
    Proxy(
            ProxyConfig config,
            Replies replies,
            boolean requireMessageAuthenticator,
            io.radiusward.radius.dictionary.Dictionary dictionary) {
        for (ProxyConfig.Realm realm : config.realms()) {
            if (realm.rewrite().any()) {
                if (dictionary == null) {
                    throw new io.radiusward.common.config.ConfigException(
                            "realm " + realm.name() + ": rewriting needs the dictionary");
                }
                realm.rewrite().compile(dictionary, "realm " + realm.name() + ": ");
            }
        }
        this.config = config;
        this.replies = replies;
        this.requireMessageAuthenticator = requireMessageAuthenticator;
        this.homes = new HomeServers(config);
        this.discovered =
                config.discovery() != ProxyConfig.Discovery.OFF ? DiscoveredRealms.of(config.discovery()) : null;
        capacity = config.pending();
        packets = new UnsafeBuffer(new byte[capacity * RadiusPacket.MAX_LENGTH]);
        ourAuthenticators = new UnsafeBuffer(new byte[capacity * 16]);
        nasAuthenticators = new UnsafeBuffer(new byte[capacity * 16]);
        home = new int[capacity];
        identifier = new int[capacity];
        nasIdentifier = new int[capacity];
        length = new int[capacity];
        sent = new int[capacity];
        generation = new int[capacity];
        deadline = new long[capacity];
        cacheKey = new long[capacity];
        route = new long[capacity];
        from = new InetSocketAddress[capacity];
        nas = new NasClient[capacity];
        inUse = new boolean[capacity];
        realmOfSlot = new ProxyConfig.Realm[capacity];
        codec = new ProxyCodec(packets, ourAuthenticators, nasAuthenticators, reply);
        free = new int[capacity];
        for (int i = 0; i < capacity; i++) {
            free[i] = capacity - 1 - i;
        }
        freeCount = capacity;
    }

    void open(String host) throws IOException {
        channel = DatagramChannel.open();
        channel.bind(new InetSocketAddress(host, 0));
        channel.configureBlocking(false);
        selector = java.nio.channels.Selector.open();
    }

    ProxyConfig config() {
        return config;
    }

    /**
     * Takes an Access-Request of a proxied realm: sent on to a home server of its pool.
     *
     * @param request the request, wrapped on the agent's receive buffer and already checked
     * @return {@link #TAKEN}, or {@link #DROPPED} when no home server can take it (the NAS asks again)
     */
    int offer(
            RadiusPacket request,
            ProxyConfig.Realm realm,
            NasClient client,
            InetSocketAddress sender,
            long via,
            long key,
            long now) {
        int[] pool = !realm.discover()
                ? homes.pool(realm.pool())
                : discovered == null ? null : discovered.pool(realm.name(), now, homes::discovered);
        if (pool == null || pool.length == 0) {
            return DROPPED; // a realm being looked up, or publishing no server: the NAS asks again
        }
        HomeState h = homes.choose(realm.discover() ? null : realm.pool(), pool, request);
        if (freeCount == 0) {
            return DROPPED;
        }
        int slot = free[--freeCount];
        int id = h.allocateId(slot);
        if (id < 0) {
            free[freeCount++] = slot;
            return DROPPED;
        }
        int len = codec.request(request, realm, client.secret(), h.config.secret(), slot, generation[slot], id);
        if (len < 0) {
            h.slotById[id] = -1;
            free[freeCount++] = slot;
            return DROPPED;
        }
        inUse[slot] = true;
        realmOfSlot[slot] = realm;
        home[slot] = h.index;
        identifier[slot] = id;
        nasIdentifier[slot] = request.identifier();
        length[slot] = len;
        sent[slot] = 0;
        cacheKey[slot] = key;
        route[slot] = via;
        from[slot] = sender;
        nas[slot] = client;
        request.buffer().getBytes(request.authenticatorOffset(), nasAuthenticators, slot * 16, 16);
        h.counts.incrementAndGet(Counter.REQUESTS.ordinal());
        transmit(slot, now);
        return TAKEN;
    }

    // ---- dynamic discovery (RFC 7585) -----------------------------------------------------------

    private final DiscoveredRealms discovered; // null without discovery

    private void transmit(int slot, long now) {
        HomeState h = homes.get(home[slot]);
        if (h.tls != null && !h.tls.lossy()) {
            transmitTls(h, slot, now);
            return;
        }
        try {
            if (h.tls != null) { // DTLS: sent again like over UDP
                if (!h.tls.open()) {
                    h.tls.connect(selector);
                }
                h.tls.send(packets, slot * RadiusPacket.MAX_LENGTH, length[slot]);
            } else {
                sendBuffer.clear();
                sendBuffer.put(packets.byteArray(), slot * RadiusPacket.MAX_LENGTH, length[slot]);
                sendBuffer.flip();
                channel.send(sendBuffer, h.address);
            }
        } catch (IOException e) {
            LOG.debug("proxy send to {} failed: {}", h.address, e.toString());
            if (h.tls != null) {
                h.tls.close();
            }
        }
        if (sent[slot]++ > 0) {
            h.counts.incrementAndGet(Counter.RESENT.ordinal());
        }
        deadline[slot] = now + config.timeout().toNanos();
        if (h.waitingSince == 0) {
            h.waitingSince = now;
        }
    }

    /**
     * Over TLS a request is written once (RFC 6613 §2.6.1: no retransmission on a connection) and waits as long as
     * all tries over UDP would; the connection is opened by the first request or probe.
     */
    private void transmitTls(HomeState h, int slot, long now) {
        sent[slot] = config.retries() + 1;
        deadline[slot] = now + config.timeout().toNanos() * (config.retries() + 1);
        if (h.waitingSince == 0) {
            h.waitingSince = now;
        }
        try {
            if (!h.tls.open()) {
                h.tls.connect(selector);
            }
            h.tls.send(packets, slot * RadiusPacket.MAX_LENGTH, length[slot]);
        } catch (IOException e) {
            LOG.debug("RadSec to home server {} failed: {}", h.config.name(), e.toString());
            h.tls.close();
        }
    }

    private void onTlsPacket(UnsafeBuffer buffer, int offset, int len) {
        received.putBytes(0, buffer, offset, len);
        onAnswer(reading, len, now);
    }

    /** Answers from home servers, timeouts, health; returns the work done. */
    int poll(long now) throws IOException {
        this.now = now;
        int work = 0;
        if (selector.selectNow() > 0) {
            for (java.util.Iterator<java.nio.channels.SelectionKey> it =
                            selector.selectedKeys().iterator();
                    it.hasNext(); ) {
                java.nio.channels.SelectionKey key = it.next();
                it.remove();
                work++;
                if (key.isValid() && key.attachment() instanceof HomeConnection client) {
                    reading = homes.of(client);
                    try {
                        client.onSelected(tlsPackets);
                    } catch (IOException e) {
                        LOG.debug("RadSec to home server {}: {}", reading.config.name(), e.toString());
                        client.close(); // waiting requests time out; the next request or probe reconnects
                    }
                }
            }
        }
        for (int i = 0; i < 64; i++) {
            receiveBuffer.clear();
            SocketAddress sender = channel.receive(receiveBuffer);
            if (sender == null) {
                break;
            }
            work++;
            HomeState h = homes.at(sender);
            if (h != null) {
                onAnswer(h, receiveBuffer.position(), now);
            }
        }
        if (now - nextTimeoutCheck >= 0) {
            nextTimeoutCheck = now + 10_000_000L;
            work += timeouts(now);
            homes.health(now, this::probe);
        }
        return work;
    }

    private void onAnswer(HomeState h, int len, long now) {
        if (response.wrap(received, 0, len) != DecodeStatus.OK) {
            h.counts.incrementAndGet(Counter.INVALID.ordinal());
            return;
        }
        int id = response.identifier();
        if (id == h.statusId) {
            statusAuth.putBytes(0, h.statusAuthenticator);
            if (authenticator.verifyResponse(response, statusAuth, 0, h.config.secret())) {
                h.slotById[id] = -1;
                h.statusId = -1;
                homes.alive(h);
            }
            return;
        }
        int slot = h.slotById[id];
        if (slot < 0 || !inUse[slot] || homes.get(home[slot]) != h) {
            h.counts.incrementAndGet(Counter.INVALID.ordinal());
            return;
        }
        int code = response.code();
        if ((code != RadiusCode.ACCESS_ACCEPT
                        && code != RadiusCode.ACCESS_REJECT
                        && code != RadiusCode.ACCESS_CHALLENGE)
                || !authenticator.verifyResponse(
                        response, ourAuthenticators, slot * 16, h.config.secret(), requireMessageAuthenticator)) {
            h.counts.incrementAndGet(Counter.INVALID.ordinal());
            return;
        }
        homes.alive(h);
        h.counts.incrementAndGet((code == RadiusCode.ACCESS_ACCEPT
                        ? Counter.ACCEPTED
                        : code == RadiusCode.ACCESS_REJECT ? Counter.REJECTED : Counter.CHALLENGED)
                .ordinal());
        int out = codec.answer(
                response, code, nasIdentifier[slot], realmOfSlot[slot], h.config.secret(), nas[slot].secret(), slot);
        if (out > 0) {
            replies.reply(replyBuffer, reply, out, from[slot], route[slot], cacheKey[slot]);
        } else {
            replies.drop(cacheKey[slot]);
        }
        release(slot);
    }

    private int timeouts(long now) {
        int work = 0;
        for (int slot = 0; slot < capacity; slot++) {
            if (!inUse[slot] || now - deadline[slot] < 0) {
                continue;
            }
            work++;
            if (sent[slot] <= config.retries()) {
                transmit(slot, now);
            } else {
                homes.get(home[slot]).counts.incrementAndGet(Counter.TIMEOUTS.ordinal());
                replies.drop(cacheKey[slot]);
                release(slot);
            }
        }
        return work;
    }

    /** Status-Server (RFC 5997) with a Message-Authenticator; any valid answer means the server is up. */
    private void probe(HomeState h) {
        if (h.statusId >= 0) {
            h.slotById[h.statusId] = -1; // the last probe went unanswered
        }
        int id = h.allocateId(STATUS_ID);
        if (id < 0) {
            return;
        }
        h.statusId = id;
        random.nextBytes(h.statusAuthenticator);
        sending.putByte(0, (byte) RadiusCode.STATUS_SERVER);
        sending.putByte(1, (byte) id);
        sending.putShort(2, (short) 38, ByteOrder.BIG_ENDIAN);
        sending.putBytes(4, h.statusAuthenticator);
        sending.putByte(20, (byte) MESSAGE_AUTHENTICATOR);
        sending.putByte(21, (byte) 18);
        sending.setMemory(22, 16, (byte) 0);
        authenticator.signAccessRequest(sending, 0, 38, RadiusPacket.HEADER_LENGTH, h.config.secret());
        try {
            if (h.tls != null) {
                if (!h.tls.open()) {
                    h.tls.connect(selector);
                }
                h.tls.send(sending, 0, 38);
            } else {
                sendBuffer.clear().limit(38);
                channel.send(sendBuffer, h.address);
            }
        } catch (IOException e) {
            LOG.debug("Status-Server to {} failed: {}", h.address, e.toString());
            if (h.tls != null) {
                h.tls.close();
            }
        }
    }

    private void release(int slot) {
        HomeState h = homes.get(home[slot]);
        if (h.slotById[identifier[slot]] == slot) {
            h.slotById[identifier[slot]] = -1;
        }
        inUse[slot] = false;
        realmOfSlot[slot] = null;
        from[slot] = null;
        nas[slot] = null;
        generation[slot] = (generation[slot] + 1) & 0xFFFF;
        free[freeCount++] = slot;
    }

    int inFlight() {
        return capacity - freeCount;
    }

    List<HomeState> homes() {
        return homes.all();
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        homes.writeMetrics(w, gateway);
    }

    void close() {
        if (discovered != null) {
            discovered.close();
        }
        homes.close();
        try {
            if (selector != null) {
                selector.close();
            }
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            LOG.debug("closing the proxy socket: {}", e.toString());
        }
    }
}
