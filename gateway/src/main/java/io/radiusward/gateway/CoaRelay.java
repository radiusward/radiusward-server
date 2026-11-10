/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLongArray;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * CoA and Disconnect-Requests from home servers, relayed to the NAS (RFC 5176 §3.1, ADR 0043). A home server of a
 * proxied realm with {@code home.<id>.coa = true} sends them here ({@code proxy.coa.port}) for its users. A request is
 * checked with that home server's secret (Request Authenticator, and its Message-Authenticator if present), then sent
 * on by {@link CoaService#relay}: its attributes as they came, without Proxy-State and Message-Authenticator, to the
 * NAS of the user's session, signed for that NAS. The NAS's ACK or NAK goes back to the home server with the request's
 * Proxy-State, signed with its secret. No session or NAS: NAK with Error-Cause 503 (Session Context Not Found); no
 * answer from the NAS: NAK with 506 (Resources Unavailable). A retransmission gets the answer again, or nothing while
 * the request is under way. Runs on its own thread: finding the session asks the cluster and may wait.
 */
final class CoaRelay implements AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(CoaRelay.class);
    private static final int PROXY_STATE = 33;
    private static final int MESSAGE_AUTHENTICATOR = 80;
    private static final int ERROR_CAUSE = 101;
    static final int SESSION_CONTEXT_NOT_FOUND = 503;
    static final int RESOURCES_UNAVAILABLE = 506;
    private static final long REMEMBER_MS = 30_000;

    enum Counter {
        RECEIVED,
        UNKNOWN_SENDER,
        BAD_AUTHENTICATOR,
        MALFORMED,
        DUPLICATE,
        ACK,
        NAK,
        NO_SESSION,
        NO_ANSWER
    }

    private final ProxyConfig config;
    private final CoaService coa;
    private final String host;
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    /** Answers sent and requests under way, by home server address, identifier and authenticator. */
    private final Map<String, Answer> recent = new ConcurrentHashMap<>();

    private DatagramChannel channel;
    private Thread thread;

    private record Answer(byte[] packet, long at) {}

    CoaRelay(ProxyConfig config, CoaService coa, String host) {
        this.config = config;
        this.coa = coa;
        this.host = host;
    }

    void start() throws IOException {
        channel = DatagramChannel.open();
        channel.bind(new InetSocketAddress(host, config.coaPort()));
        thread = new Thread(this::receive, "coa-relay");
        thread.setDaemon(true);
        thread.start();
        LOG.info("relaying CoA from home servers on {}", channel.getLocalAddress());
    }

    int port() {
        try {
            return ((InetSocketAddress) channel.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    private void receive() {
        ByteBuffer in = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
        while (channel.isOpen()) {
            try {
                in.clear();
                InetSocketAddress from = (InetSocketAddress) channel.receive(in);
                handle(Arrays.copyOf(in.array(), in.position()), from);
            } catch (ClosedChannelException e) {
                return;
            } catch (IOException | RuntimeException e) {
                LOG.debug("CoA relay: {}", e.toString());
            }
        }
    }

    private void handle(byte[] data, InetSocketAddress from) throws IOException {
        increment(Counter.RECEIVED);
        ProxyConfig.Home home = config.homes().values().stream()
                .filter(ProxyConfig.Home::relaysCoa)
                .filter(h -> h.address().equals(from.getAddress()))
                .findFirst()
                .orElse(null);
        if (home == null) {
            increment(Counter.UNKNOWN_SENDER);
            return;
        }
        RadiusPacket p = new RadiusPacket();
        UnsafeBuffer buffer = new UnsafeBuffer(data);
        if (p.wrap(buffer, 0, data.length) != DecodeStatus.OK
                || (p.code() != DynamicAuthorization.COA_REQUEST
                        && p.code() != DynamicAuthorization.DISCONNECT_REQUEST)) {
            increment(Counter.MALFORMED);
            return;
        }
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        if (!authenticator.verifyAccountingRequest(p, home.secret())
                || (p.hasMessageAuthenticator()
                        && !authenticator.verifyRequestMessageAuthenticator(p, home.secret()))) {
            increment(Counter.BAD_AUTHENTICATOR);
            return;
        }
        long now = System.currentTimeMillis();
        recent.values().removeIf(a -> now - a.at() > REMEMBER_MS);
        String key = from.getAddress().getHostAddress() + "/" + p.identifier() + "/"
                + java.util.HexFormat.of().formatHex(data, 4, 20);
        Answer known = recent.putIfAbsent(key, new Answer(null, now));
        if (known != null) {
            increment(Counter.DUPLICATE);
            if (known.packet() != null) {
                channel.send(ByteBuffer.wrap(known.packet()), from);
            }
            return;
        }
        ByteArrayOutputStream forward = new ByteArrayOutputStream();
        ByteArrayOutputStream proxyStates = new ByteArrayOutputStream();
        for (int at = p.attributesOffset(); at < p.attributesEnd(); ) {
            int type = data[at] & 0xFF;
            int length = data[at + 1] & 0xFF;
            if (type == PROXY_STATE) {
                proxyStates.write(data, at, length);
            } else if (type != MESSAGE_AUTHENTICATOR) {
                forward.write(data, at, length);
            }
            at += length;
        }
        CompletableFuture<DynamicAuthorization.Result> result;
        try {
            result = coa.relay(p.code(), forward.toByteArray());
        } catch (TimeoutException e) {
            result = null;
        }
        if (result == null) {
            increment(Counter.NO_SESSION);
            answer(key, from, home, data, false, SESSION_CONTEXT_NOT_FOUND, proxyStates.toByteArray());
            return;
        }
        byte[] states = proxyStates.toByteArray();
        result.whenComplete((r, e) -> {
            try {
                if (e != null
                        || r == null
                        || r.outcome() == DynamicAuthorization.Outcome.TIMEOUT
                        || r.outcome() == DynamicAuthorization.Outcome.UNREACHABLE) {
                    increment(Counter.NO_ANSWER);
                    answer(key, from, home, data, false, RESOURCES_UNAVAILABLE, states);
                } else {
                    boolean ack = r.outcome() == DynamicAuthorization.Outcome.ACK;
                    increment(ack ? Counter.ACK : Counter.NAK);
                    answer(key, from, home, data, ack, r.errorCause(), states);
                }
            } catch (IOException io) {
                LOG.debug("CoA relay answer to {}: {}", from, io.toString());
            }
        });
    }

    /** ACK or NAK (with Error-Cause) to the home server, its Proxy-State echoed, signed with its secret. */
    private void answer(
            String key,
            InetSocketAddress to,
            ProxyConfig.Home home,
            byte[] request,
            boolean ack,
            int errorCause,
            byte[] proxyStates)
            throws IOException {
        int code = (request[0] & 0xFF) + (ack ? 1 : 2);
        UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(out, 0).header(code, request[1] & 0xFF);
        int ma = enc.messageAuthenticator();
        if (!ack && errorCause > 0) {
            enc.uint32(ERROR_CAUSE, errorCause);
        }
        if (proxyStates.length > 0) {
            enc.rawAttributes(new UnsafeBuffer(proxyStates), 0, proxyStates.length);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signResponse(out, 0, length, ma, new UnsafeBuffer(request), 4, home.secret());
        byte[] packet = Arrays.copyOf(out.byteArray(), length);
        recent.put(key, new Answer(packet, System.currentTimeMillis()));
        channel.send(ByteBuffer.wrap(packet), to);
    }

    private void increment(Counter counter) {
        counts.incrementAndGet(counter.ordinal());
    }

    long get(Counter counter) {
        return counts.get(counter.ordinal());
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter("radiusward_gateway_coa_relay_total", "CoA and Disconnect-Requests from home servers, relayed");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(Locale.ROOT));
        }
    }

    @Override
    public void close() {
        try {
            if (channel != null) {
                channel.close();
            }
        } catch (IOException e) {
            LOG.debug("closing the CoA relay: {}", e.toString());
        }
    }
}
