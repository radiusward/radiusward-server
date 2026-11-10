/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.AccessRequests;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLongArray;
import org.agrona.BufferUtil;
import org.agrona.DirectBuffer;
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

    private static final int USER_NAME = 1;
    private static final int USER_PASSWORD = 2;
    private static final int CHAP_PASSWORD = 3;
    private static final int VENDOR_SPECIFIC = 26;
    private static final int CALLING_STATION_ID = 31;
    private static final int PROXY_STATE = 33;
    private static final int CHAP_CHALLENGE = 60;
    private static final int TUNNEL_PASSWORD = 69;
    private static final int MESSAGE_AUTHENTICATOR = 80;
    private static final int MICROSOFT = 311;
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

    /** A home server: its identifiers in flight, its health, its counters. */
    static final class HomeState {
        final ProxyConfig.Home config;
        final InetSocketAddress address;
        final int[] slotById = new int[256];
        final byte[] statusAuthenticator = new byte[16];
        final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
        int nextId;
        volatile boolean alive = true;
        long waitingSince; // first request sent since the last answer; 0 while answered
        long nextStatus;
        int statusId = -1;

        HomeState(ProxyConfig.Home config) {
            this.config = config;
            this.address = new InetSocketAddress(config.address(), config.port());
            java.util.Arrays.fill(slotById, -1);
        }

        int allocateId(int slot) {
            for (int n = 0; n < 256; n++) {
                int id = (nextId + n) & 0xFF;
                if (slotById[id] == -1) {
                    slotById[id] = slot;
                    nextId = (id + 1) & 0xFF;
                    return id;
                }
            }
            return -1;
        }
    }

    private final ProxyConfig config;
    private final Replies replies;
    private final boolean requireMessageAuthenticator;
    private final HomeState[] homes;
    private final Map<InetSocketAddress, HomeState> byAddress = new HashMap<>();
    private final Map<String, int[]> pools = new HashMap<>();
    private final Map<String, Boolean> loadBalanced = new HashMap<>();
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccessRequests credentials = new AccessRequests();
    private final SaltedValues salted = new SaltedValues();
    private final SecureRandom random = new SecureRandom();
    private final RadiusPacket response = new RadiusPacket();
    private final byte[] token = new byte[8]; // Proxy-State: 4 random bytes of this gateway, slot, generation

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
    private final int[] free;
    private int freeCount;

    private final ByteBuffer receiveBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer received = new UnsafeBuffer(receiveBuffer);
    private final ByteBuffer replyBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer reply = new UnsafeBuffer(replyBuffer);
    private final ByteBuffer sendBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH, 64);
    private final UnsafeBuffer sending = new UnsafeBuffer(sendBuffer);
    private final UnsafeBuffer plain = new UnsafeBuffer(new byte[256]);
    private final UnsafeBuffer cipher = new UnsafeBuffer(new byte[256]);
    private final UnsafeBuffer statusAuth = new UnsafeBuffer(new byte[16]);
    private final byte[] authScratch = new byte[16];
    private DatagramChannel channel;
    private long nextTimeoutCheck;

    Proxy(ProxyConfig config, Replies replies, boolean requireMessageAuthenticator) {
        this.config = config;
        this.replies = replies;
        this.requireMessageAuthenticator = requireMessageAuthenticator;
        List<HomeState> list = new ArrayList<>();
        Map<String, Integer> index = new HashMap<>();
        for (ProxyConfig.Home h : config.homes().values()) {
            if (h.tls()) {
                continue; // RadSec home servers: milestone 4 (TlsHomes)
            }
            index.put(h.name(), list.size());
            HomeState s = new HomeState(h);
            list.add(s);
            byAddress.put(s.address, s);
        }
        homes = list.toArray(HomeState[]::new);
        for (ProxyConfig.Pool p : config.pools().values()) {
            pools.put(
                    p.name(),
                    p.servers().stream()
                            .filter(index::containsKey)
                            .mapToInt(index::get)
                            .toArray());
            loadBalanced.put(p.name(), p.loadBalance());
        }
        random.nextBytes(token);
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
        int[] pool = realm.pool() == null ? null : pools.get(realm.pool());
        if (pool == null || pool.length == 0) {
            return DROPPED; // discovered realms (RFC 7585) and TLS pools: milestones 4 and 6
        }
        HomeState h = choose(realm.pool(), pool, request);
        if (freeCount == 0) {
            return DROPPED;
        }
        int slot = free[--freeCount];
        int id = h.allocateId(slot);
        if (id < 0) {
            free[freeCount++] = slot;
            return DROPPED;
        }
        int len = encode(request, realm, client, h, slot, id);
        if (len < 0) {
            h.slotById[id] = -1;
            free[freeCount++] = slot;
            return DROPPED;
        }
        inUse[slot] = true;
        home[slot] = indexOf(h);
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

    private int indexOf(HomeState h) {
        for (int i = 0; i < homes.length; i++) {
            if (homes[i] == h) {
                return i;
            }
        }
        return -1;
    }

    /** Failover: the first one alive. Load-balance: by device (Calling-Station-Id, else User-Name) among those alive. */
    private HomeState choose(String poolName, int[] pool, RadiusPacket request) {
        int alive = 0;
        for (int i : pool) {
            if (homes[i].alive) {
                alive++;
            }
        }
        if (alive == 0) {
            return homes[pool[0]]; // all dead: try the first; a request is as good a probe as a Status-Server
        }
        int pick = 0;
        if (Boolean.TRUE.equals(loadBalanced.get(poolName)) && alive > 1) {
            int at = request.findAttribute(CALLING_STATION_ID);
            if (at < 0) {
                at = request.findAttribute(USER_NAME);
            }
            int h = 0;
            if (at >= 0) {
                for (int i = 2, n = request.buffer().getByte(at + 1) & 0xFF; i < n; i++) {
                    h = h * 31 + request.buffer().getByte(at + i);
                }
            }
            pick = Math.floorMod(h, alive);
        }
        for (int i : pool) {
            if (homes[i].alive && pick-- == 0) {
                return homes[i];
            }
        }
        return homes[pool[0]];
    }

    /** The request for the home server into the slot's buffer; its length, or -1 if it does not fit. */
    private int encode(RadiusPacket request, ProxyConfig.Realm realm, NasClient client, HomeState h, int slot, int id) {
        UnsafeBuffer out = packets;
        int o = slot * RadiusPacket.MAX_LENGTH;
        int end = o + RadiusPacket.MAX_LENGTH;
        out.putByte(o, (byte) RadiusCode.ACCESS_REQUEST);
        out.putByte(o + 1, (byte) id);
        random.nextBytes(authScratch);
        out.putBytes(o + 4, authScratch);
        out.getBytes(o + 4, ourAuthenticators, slot * 16, 16);
        int w = o + RadiusPacket.HEADER_LENGTH;
        int ma = w;
        out.putByte(w, (byte) MESSAGE_AUTHENTICATOR);
        out.putByte(w + 1, (byte) 18);
        out.setMemory(w + 2, 16, (byte) 0);
        w += 18;
        DirectBuffer in = request.buffer();
        boolean chap = false;
        boolean challenge = false;
        for (int at = request.attributesOffset(); at < request.attributesEnd(); ) {
            int type = in.getByte(at) & 0xFF;
            int l = in.getByte(at + 1) & 0xFF;
            if (type == MESSAGE_AUTHENTICATOR) {
                at += l;
                continue;
            }
            if (type == USER_PASSWORD) {
                int n = credentials.decryptUserPassword(request, client.secret(), plain, 0);
                if (n < 0) {
                    return -1;
                }
                int c = credentials.encryptUserPassword(plain, 0, n, out, o + 4, h.config.secret(), cipher, 0);
                if (w + 2 + c > end) {
                    return -1;
                }
                out.putByte(w, (byte) USER_PASSWORD);
                out.putByte(w + 1, (byte) (2 + c));
                out.putBytes(w + 2, cipher, 0, c);
                w += 2 + c;
            } else if (type == USER_NAME && realm.strip()) {
                int start = at + 2;
                int stop = at + l;
                for (int i = at + 2; i < at + l; i++) {
                    byte b = in.getByte(i);
                    if (b == '@') {
                        stop = i;
                        break;
                    }
                    if (b == '\\' && start == at + 2) {
                        start = i + 1;
                    }
                }
                if (w + 2 + (stop - start) > end) {
                    return -1;
                }
                out.putByte(w, (byte) USER_NAME);
                out.putByte(w + 1, (byte) (2 + stop - start));
                out.putBytes(w + 2, in, start, stop - start);
                w += 2 + stop - start;
            } else {
                chap |= type == CHAP_PASSWORD;
                challenge |= type == CHAP_CHALLENGE;
                if (w + l > end) {
                    return -1;
                }
                out.putBytes(w, in, at, l);
                w += l;
            }
            at += l;
        }
        if (chap && !challenge) { // the original Request Authenticator was the challenge (RFC 2865 §2.2)
            if (w + 18 > end) {
                return -1;
            }
            out.putByte(w, (byte) CHAP_CHALLENGE);
            out.putByte(w + 1, (byte) 18);
            out.putBytes(w + 2, in, request.authenticatorOffset(), 16);
            w += 18;
        }
        if (w + 10 > end) {
            return -1;
        }
        out.putByte(w, (byte) PROXY_STATE);
        out.putByte(w + 1, (byte) 10);
        out.putBytes(w + 2, token, 0, 4);
        out.putShort(w + 6, (short) slot, ByteOrder.BIG_ENDIAN);
        out.putShort(w + 8, (short) generation[slot], ByteOrder.BIG_ENDIAN);
        w += 10;
        int len = w - o;
        out.putShort(o + 2, (short) len, ByteOrder.BIG_ENDIAN);
        authenticator.signAccessRequest(out, o, len, ma, h.config.secret());
        return len;
    }

    private void transmit(int slot, long now) {
        HomeState h = homes[home[slot]];
        sendBuffer.clear();
        sendBuffer.put(packets.byteArray(), slot * RadiusPacket.MAX_LENGTH, length[slot]);
        sendBuffer.flip();
        try {
            channel.send(sendBuffer, h.address);
        } catch (IOException e) {
            LOG.debug("proxy send to {} failed: {}", h.address, e.toString());
        }
        if (sent[slot]++ > 0) {
            h.counts.incrementAndGet(Counter.RESENT.ordinal());
        }
        deadline[slot] = now + config.timeout().toNanos();
        if (h.waitingSince == 0) {
            h.waitingSince = now;
        }
    }

    /** Answers from home servers, timeouts, health; returns the work done. */
    int poll(long now) throws IOException {
        int work = 0;
        for (int i = 0; i < 64; i++) {
            receiveBuffer.clear();
            SocketAddress sender = channel.receive(receiveBuffer);
            if (sender == null) {
                break;
            }
            work++;
            HomeState h = byAddress.get(sender);
            if (h != null) {
                onAnswer(h, receiveBuffer.position(), now);
            }
        }
        if (now - nextTimeoutCheck >= 0) {
            nextTimeoutCheck = now + 10_000_000L;
            work += timeouts(now);
            health(now);
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
                alive(h);
            }
            return;
        }
        int slot = h.slotById[id];
        if (slot < 0 || !inUse[slot] || homes[home[slot]] != h) {
            h.counts.incrementAndGet(Counter.INVALID.ordinal());
            return;
        }
        int code = response.code();
        if ((code != RadiusCode.ACCESS_ACCEPT
                        && code != RadiusCode.ACCESS_REJECT
                        && code != RadiusCode.ACCESS_CHALLENGE)
                || !authenticator.verifyResponse(response, ourAuthenticators, slot * 16, h.config.secret())
                || (response.hasMessageAuthenticator()
                        ? !authenticator.verifyResponseMessageAuthenticator(
                                response, ourAuthenticators, slot * 16, h.config.secret())
                        : requireMessageAuthenticator)) {
            h.counts.incrementAndGet(Counter.INVALID.ordinal());
            return;
        }
        alive(h);
        h.counts.incrementAndGet((code == RadiusCode.ACCESS_ACCEPT
                        ? Counter.ACCEPTED
                        : code == RadiusCode.ACCESS_REJECT ? Counter.REJECTED : Counter.CHALLENGED)
                .ordinal());
        int out = answer(h, slot, code);
        if (out > 0) {
            replies.reply(replyBuffer, reply, out, from[slot], route[slot], cacheKey[slot]);
        } else {
            replies.drop(cacheKey[slot]);
        }
        release(slot);
    }

    private void alive(HomeState h) {
        h.waitingSince = 0;
        if (!h.alive) {
            h.alive = true;
            LOG.info("home server {} ({}) answers again", h.config.name(), h.address);
        }
    }

    /** The home server's answer for the NAS: its length in the reply buffer, or -1. */
    private int answer(HomeState h, int slot, int code) {
        NasClient client = nas[slot];
        reply.putByte(0, (byte) code);
        reply.putByte(1, (byte) nasIdentifier[slot]);
        int w = RadiusPacket.HEADER_LENGTH;
        reply.putByte(w, (byte) MESSAGE_AUTHENTICATOR);
        reply.putByte(w + 1, (byte) 18);
        reply.setMemory(w + 2, 16, (byte) 0);
        w += 18;
        DirectBuffer in = response.buffer();
        for (int at = response.attributesOffset(); at < response.attributesEnd(); ) {
            int type = in.getByte(at) & 0xFF;
            int l = in.getByte(at + 1) & 0xFF;
            boolean ours = type == PROXY_STATE && l == 10 && sameToken(in, at + 2, slot);
            if (type != MESSAGE_AUTHENTICATOR && !ours) {
                if (w + l > RadiusPacket.MAX_LENGTH) {
                    return -1;
                }
                reply.putBytes(w, in, at, l);
                if (!reencrypt(type, w, l, h, slot, client)) {
                    return -1;
                }
                w += l;
            }
            at += l;
        }
        reply.putShort(2, (short) w, ByteOrder.BIG_ENDIAN);
        authenticator.signResponse(
                reply, 0, w, RadiusPacket.HEADER_LENGTH, nasAuthenticators, slot * 16, client.secret());
        return w;
    }

    private boolean sameToken(DirectBuffer in, int at, int slot) {
        for (int i = 0; i < 4; i++) {
            if (in.getByte(at + i) != token[i]) {
                return false;
            }
        }
        return (in.getShort(at + 4, ByteOrder.BIG_ENDIAN) & 0xFFFF) == slot;
    }

    /** MS-MPPE-Send/Recv-Key and Tunnel-Password, copied to the reply at {@code w}, for the NAS's secret. */
    private boolean reencrypt(int type, int w, int l, HomeState h, int slot, NasClient client) {
        if (type == TUNNEL_PASSWORD && l > 3) {
            return salted.reencrypt(
                    reply,
                    w + 3,
                    l - 3,
                    h.config.secret(),
                    ourAuthenticators,
                    slot * 16,
                    client.secret(),
                    nasAuthenticators,
                    slot * 16);
        }
        if (type == VENDOR_SPECIFIC && l > 8 && reply.getInt(w + 2, ByteOrder.BIG_ENDIAN) == MICROSOFT) {
            for (int p = w + 6; p + 2 <= w + l; ) {
                int sub = reply.getByte(p) & 0xFF;
                int sl = reply.getByte(p + 1) & 0xFF;
                if (sl < 2 || p + sl > w + l) {
                    return false;
                }
                if ((sub == 16 || sub == 17)
                        && !salted.reencrypt(
                                reply,
                                p + 2,
                                sl - 2,
                                h.config.secret(),
                                ourAuthenticators,
                                slot * 16,
                                client.secret(),
                                nasAuthenticators,
                                slot * 16)) {
                    return false;
                }
                p += sl;
            }
        }
        return true;
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
                homes[home[slot]].counts.incrementAndGet(Counter.TIMEOUTS.ordinal());
                replies.drop(cacheKey[slot]);
                release(slot);
            }
        }
        return work;
    }

    private void health(long now) {
        long dead = config.deadAfter().toNanos();
        for (HomeState h : homes) {
            if (h.alive && h.waitingSince != 0 && now - h.waitingSince > dead) {
                h.alive = false;
                LOG.warn(
                        "home server {} ({}) is dead: no answer for {}",
                        h.config.name(),
                        h.address,
                        config.deadAfter());
            }
            if (now - h.nextStatus >= 0) {
                h.nextStatus = now + config.statusInterval().toNanos();
                probe(h);
            }
        }
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
        sendBuffer.clear().limit(38);
        try {
            channel.send(sendBuffer, h.address);
        } catch (IOException e) {
            LOG.debug("Status-Server to {} failed: {}", h.address, e.toString());
        }
    }

    private void release(int slot) {
        HomeState h = homes[home[slot]];
        if (h.slotById[identifier[slot]] == slot) {
            h.slotById[identifier[slot]] = -1;
        }
        inUse[slot] = false;
        from[slot] = null;
        nas[slot] = null;
        generation[slot] = (generation[slot] + 1) & 0xFFFF;
        free[freeCount++] = slot;
    }

    int inFlight() {
        return capacity - freeCount;
    }

    HomeState[] homes() {
        return homes;
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter("radiusward_gateway_proxy_requests_total", "Access-Requests proxied to home servers (ADR 0037)");
        for (HomeState h : homes) {
            for (Counter c : Counter.values()) {
                w.sample(
                        h.counts.get(c.ordinal()),
                        "gateway",
                        gateway,
                        "home",
                        h.config.name(),
                        "result",
                        c.name().toLowerCase(Locale.ROOT));
            }
        }
        w.gauge("radiusward_gateway_proxy_home_alive", "1 while a home server answers");
        for (HomeState h : homes) {
            w.sample(h.alive ? 1 : 0, "gateway", gateway, "home", h.config.name());
        }
    }

    void close() {
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            LOG.debug("closing the proxy socket: {}", e.toString());
        }
    }
}
