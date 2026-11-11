/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Access-Request load beside the accounting load of {@link LoadGenerator}: {@code rate} requests per second for
 * {@code duration}, round-robin over the users, methods and servers, with a share of deliberately wrong passwords so
 * that rejects show up too. Unanswered requests are retransmitted unchanged, as a NAS does. A wrong password that is
 * accepted, or a right one that is rejected, counts as unexpected.
 */
final class AccessLoad {

    record Settings(
            List<InetSocketAddress> servers,
            byte[] secret,
            List<String> users,
            String password,
            List<AccessCredentials.Method> methods,
            int rate,
            double rejectRatio,
            Duration duration,
            Duration timeout,
            int retries) {}

    record Result(
            long sent,
            long accepted,
            long rejected,
            long challenged,
            long timeouts,
            long wrongPasswords,
            long unexpected,
            long p50Micros,
            long p99Micros) {}

    private static final int IDS_PER_CHANNEL = 256;
    /**
     * How far sending may fall behind the rate and still catch up. A stall of the process (GC, a busy host) of up to
     * this long is made good by sending faster for a moment, so the delivered rate is the requested one; only a longer
     * stall drops its share instead of bursting it all at once.
     */
    private static final long CATCH_UP_NANOS = 100_000_000L;

    private static final long TIMEOUT_SCAN_NANOS = 10_000_000L;

    private final Settings settings;
    private final PrintStream out;
    private final Random random = new java.security.SecureRandom(); // request authenticators must not be predictable
    private final AccessCredentials credentials = new AccessCredentials(random);
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final ByteBuffer receive = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final RadiusPacket view = new RadiusPacket();

    private static final class Request {
        byte[] bytes;
        boolean wrongPassword;
        int attempts;
        long firstSentNanos;
        long deadlineNanos;
        int server;
    }

    private static final class Port {
        final DatagramChannel channel;
        final Request[] inFlight = new Request[IDS_PER_CHANNEL];
        final ArrayDeque<Integer> freeIds = new ArrayDeque<>();

        Port(Selector selector, java.net.InetAddress local) throws IOException {
            channel = DatagramChannel.open();
            try {
                channel.bind(new InetSocketAddress(local, 0));
                channel.configureBlocking(false);
                channel.register(selector, SelectionKey.OP_READ, this);
            } catch (IOException | RuntimeException e) {
                channel.close();
                throw e;
            }
            for (int i = 0; i < IDS_PER_CHANNEL; i++) {
                freeIds.add(i);
            }
        }
    }

    AccessLoad(Settings settings, PrintStream out) {
        this.settings = settings;
        this.out = out;
    }

    Result run() throws IOException {
        long start = System.nanoTime();
        long end = start + settings.duration().toNanos();
        long gapNanos = 1_000_000_000L / Math.max(1, settings.rate());
        long nextSendAt = start;
        long sent = 0;
        long accepted = 0;
        long rejected = 0;
        long challenged = 0;
        long timeouts = 0;
        long wrong = 0;
        long unexpected = 0;
        int inFlight = 0;
        long nextTimeoutScan = 0;
        int nextServer = 0;
        List<Long> latencies = new ArrayList<>();
        try (Selector selector = Selector.open()) {
            int channels = Math.max(
                    1, settings.rate() * (int) Math.max(1, settings.timeout().toSeconds()) / 200 + 1);
            List<Port> ports = new ArrayList<>();
            for (int i = 0; i < channels; i++) {
                ports.add(new Port(selector, localAddress()));
            }
            while (true) {
                long now = System.nanoTime();
                if (now >= end && inFlight == 0) {
                    break;
                }
                while (now < end && now >= nextSendAt) {
                    Port port = free(ports);
                    if (port == null) {
                        break; // too many in flight; wait for answers or timeouts
                    }
                    int id = port.freeIds.poll();
                    Request r = new Request();
                    r.wrongPassword = random.nextDouble() < settings.rejectRatio();
                    r.bytes = encode(id, sent, r.wrongPassword);
                    r.server = nextServer;
                    nextServer = (nextServer + 1) % settings.servers().size();
                    r.attempts = 1;
                    r.firstSentNanos = now;
                    r.deadlineNanos = now + settings.timeout().toNanos();
                    port.inFlight[id] = r;
                    port.channel.send(
                            ByteBuffer.wrap(r.bytes), settings.servers().get(r.server));
                    sent++;
                    wrong += r.wrongPassword ? 1 : 0;
                    inFlight++;
                    nextSendAt += gapNanos;
                    if (nextSendAt < now - CATCH_UP_NANOS) {
                        nextSendAt = now; // a longer stall is lost rather than sent as one burst
                    }
                }

                selector.select(1);
                for (SelectionKey key : selector.selectedKeys()) {
                    Port port = (Port) key.attachment();
                    while (true) {
                        receive.clear();
                        if (port.channel.receive(receive) == null) {
                            break;
                        }
                        int length = receive.position();
                        if (view.wrap(new UnsafeBuffer(receive.array(), 0, length), 0, length) != DecodeStatus.OK) {
                            continue;
                        }
                        Request r = port.inFlight[view.identifier()];
                        if (r == null
                                || !authenticator.verifyResponse(
                                        view, new UnsafeBuffer(r.bytes), 4, settings.secret())) {
                            continue;
                        }
                        port.inFlight[view.identifier()] = null;
                        port.freeIds.add(view.identifier());
                        inFlight--;
                        latencies.add((System.nanoTime() - r.firstSentNanos) / 1000);
                        switch (view.code()) {
                            case RadiusCode.ACCESS_ACCEPT -> {
                                accepted++;
                                unexpected += r.wrongPassword ? 1 : 0;
                            }
                            case RadiusCode.ACCESS_REJECT -> {
                                rejected++;
                                unexpected += r.wrongPassword ? 0 : 1;
                            }
                            case RadiusCode.ACCESS_CHALLENGE -> challenged++;
                            default -> unexpected++;
                        }
                    }
                }
                selector.selectedKeys().clear();

                now = System.nanoTime();
                if (now < nextTimeoutScan) {
                    continue; // timeouts are seconds long: scanning every in-flight slot each loop only burns CPU
                }
                nextTimeoutScan = now + TIMEOUT_SCAN_NANOS;
                for (Port port : ports) {
                    for (int id = 0; id < IDS_PER_CHANNEL; id++) {
                        Request r = port.inFlight[id];
                        if (r != null && now > r.deadlineNanos) {
                            if (r.attempts <= settings.retries()) {
                                r.attempts++;
                                r.deadlineNanos = now + settings.timeout().toNanos();
                                port.channel.send(
                                        ByteBuffer.wrap(r.bytes),
                                        settings.servers().get(r.server));
                            } else {
                                port.inFlight[id] = null;
                                port.freeIds.add(id);
                                timeouts++;
                                inFlight--;
                            }
                        }
                    }
                }
            }
            for (Port port : ports) {
                port.channel.close();
            }
        }
        long[] sorted = latencies.stream().mapToLong(Long::longValue).sorted().toArray();
        Result result = new Result(
                sent,
                accepted,
                rejected,
                challenged,
                timeouts,
                wrong,
                unexpected,
                percentile(sorted, 50),
                percentile(sorted, 99));
        out.printf(
                "access: sent %d (%d with a wrong password), accepted %d, rejected %d, challenged %d, timeouts %d,"
                        + " unexpected %d; latency p50 %.1f ms, p99 %.1f ms%n",
                result.sent(),
                result.wrongPasswords(),
                result.accepted(),
                result.rejected(),
                result.challenged(),
                result.timeouts(),
                result.unexpected(),
                result.p50Micros() / 1000.0,
                result.p99Micros() / 1000.0);
        return result;
    }

    /** Loopback when every server is local (see {@link LoadGenerator}), otherwise the wildcard address. */
    private java.net.InetAddress localAddress() {
        boolean loopback = settings.servers().stream()
                .allMatch(s -> s.getAddress() != null && s.getAddress().isLoopbackAddress());
        return loopback ? java.net.InetAddress.getLoopbackAddress() : null;
    }

    private static Port free(List<Port> ports) {
        for (Port p : ports) {
            if (!p.freeIds.isEmpty()) {
                return p;
            }
        }
        return null;
    }

    /** Request {@code n}: its user and method round-robin, the password wrong when the request is meant to fail. */
    private byte[] encode(int identifier, long n, boolean wrong) {
        String user = settings.users().get((int) (n % settings.users().size()));
        AccessCredentials.Method method =
                settings.methods().get((int) (n % settings.methods().size()));
        byte[] requestAuthenticator = new byte[16];
        random.nextBytes(requestAuthenticator);
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, identifier)
                .authenticator(requestAuthenticator)
                .attribute(1, user)
                .ipv4(4, 0x7F000001L)
                .attribute(32, "load");
        credentials.write(
                encoder,
                requestAuthenticator,
                user,
                settings.password() + (wrong ? "x" : ""),
                method,
                settings.secret());
        int messageAuthenticator = encoder.messageAuthenticator();
        int length = encoder.finish();
        authenticator.signAccessRequest(buffer, 0, length, messageAuthenticator, settings.secret());
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    private static long percentile(long[] sorted, int p) {
        if (sorted.length == 0) {
            return 0;
        }
        return sorted[Math.min(sorted.length - 1, (int) Math.ceil(p / 100.0 * sorted.length) - 1)];
    }
}
