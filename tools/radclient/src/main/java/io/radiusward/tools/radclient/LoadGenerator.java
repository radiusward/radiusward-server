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
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Random;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Accounting load: {@code sessions} sessions spread over {@code nas} simulated NAS, each sending a Start,
 * Interim-Updates every {@code interim} and a Stop at the end, paced to {@code rate} requests per second.
 * Requests that get no response are retransmitted unchanged (as a NAS does), optionally to the next server.
 * Every event's outcome goes to the ack log, so tests can check that each acknowledged event is in the
 * cluster state.
 *
 * <p>All simulated NAS share this machine's address, so the gateway sees one NAS entry, like access points behind
 * NAT; each simulated NAS is reported in {@code NAS-Identifier} ({@code nas<n>}). Session ids are unique
 * ({@code nas<n>-<s>}), or with {@code sharedSessionIds} repeat across the simulated NAS ({@code %08X} of the
 * session's number on its NAS), as devices numbering sessions from boot do — only an entry that identifies devices
 * (ADR 0019) keeps them apart.
 */
public final class LoadGenerator {

    public record Settings(
            List<InetSocketAddress> servers,
            byte[] secret,
            int nas,
            int sessions,
            int rate,
            Duration duration,
            Duration interim,
            Duration timeout,
            int retries,
            boolean retryOtherServer,
            boolean stopAtEnd,
            Path ackLog,
            int firstSession,
            boolean sharedSessionIds) {

        /** Unique session ids. */
        public Settings(
                List<InetSocketAddress> servers,
                byte[] secret,
                int nas,
                int sessions,
                int rate,
                Duration duration,
                Duration interim,
                Duration timeout,
                int retries,
                boolean retryOtherServer,
                boolean stopAtEnd,
                Path ackLog,
                int firstSession) {
            this(
                    servers,
                    secret,
                    nas,
                    sessions,
                    rate,
                    duration,
                    interim,
                    timeout,
                    retries,
                    retryOtherServer,
                    stopAtEnd,
                    ackLog,
                    firstSession,
                    false);
        }

        /** Sessions numbered from 0. */
        public Settings(
                List<InetSocketAddress> servers,
                byte[] secret,
                int nas,
                int sessions,
                int rate,
                Duration duration,
                Duration interim,
                Duration timeout,
                int retries,
                boolean retryOtherServer,
                boolean stopAtEnd,
                Path ackLog) {
            this(
                    servers,
                    secret,
                    nas,
                    sessions,
                    rate,
                    duration,
                    interim,
                    timeout,
                    retries,
                    retryOtherServer,
                    stopAtEnd,
                    ackLog,
                    0);
        }
    }

    public record Result(
            long sent,
            long acked,
            long failed,
            long retransmissions,
            long p50Micros,
            long p99Micros,
            long maxMicros,
            double seconds) {}

    private static final int IDS_PER_CHANNEL = 256;

    private final Settings settings;
    private final PrintStream out;
    private final Random random = new Random(42);
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final ByteBuffer receive = ByteBuffer.allocate(RadiusPacket.MAX_LENGTH);
    private final RadiusPacket responseView = new RadiusPacket();
    /** Responses received that matched no request in flight (late, duplicate or not authentic). */
    private long unmatched;
    /** Sends that found the socket buffer full, and datagrams that could not be sent at all. */
    private long sendStalls;

    private long sendDropped;

    /** One request in flight. */
    private static final class Request {
        String device;
        String sessionId;
        int status;
        long sessionTime;
        byte[] bytes;
        int attempts;
        long firstSentNanos;
        long deadlineNanos;
        int server;
        int identifier;
    }

    private final class Port {
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

    /** A scheduled accounting event of one session. */
    private record Due(long atNanos, int session, int status, long sessionTime) implements Comparable<Due> {
        @Override
        public int compareTo(Due o) {
            return Long.compare(atNanos, o.atNanos);
        }
    }

    public LoadGenerator(Settings settings, PrintStream out) {
        this.settings = settings;
        this.out = out;
    }

    public Result run() throws IOException {
        long start = System.nanoTime();
        long end = start + settings.duration().toNanos();
        long interimNanos = settings.interim().toNanos();
        long gapNanos = 1_000_000_000L / Math.max(1, settings.rate());

        PriorityQueue<Due> schedule = new PriorityQueue<>();
        for (int s = 0; s < settings.sessions(); s++) {
            long offset = (long) (random.nextDouble()
                    * Math.min(interimNanos, settings.duration().toNanos() / 2));
            schedule.add(new Due(start + offset, s, 1, 0));
        }

        List<Long> latencies = new ArrayList<>();
        long sent = 0;
        long acked = 0;
        long failed = 0;
        long retransmissions = 0;
        int nextServer = 0;
        long nextSendAt = start;

        try (Selector selector = Selector.open();
                BufferedWriter log = settings.ackLog() == null
                        ? null
                        : Files.newBufferedWriter(settings.ackLog(), StandardCharsets.UTF_8)) {
            if (log != null) {
                log.write("session_id,status,session_time,acked,attempts,latency_ms,nas_identifier\n");
            }
            int channels = Math.max(
                    2, (settings.rate() * (int) Math.max(1, settings.timeout().toSeconds())) / 200 + 1);
            List<Port> ports = new ArrayList<>();
            for (int i = 0; i < channels; i++) {
                ports.add(new Port(selector, localAddress()));
            }
            boolean stopping = false;
            int inFlight = 0;

            while (true) {
                long now = System.nanoTime();
                if (!stopping && now >= end) {
                    stopping = true;
                    if (settings.stopAtEnd()) {
                        for (Due d : drainLatest(schedule)) {
                            schedule.add(new Due(now, d.session(), 2, d.sessionTime()));
                        }
                    } else {
                        schedule.clear();
                    }
                }
                if (stopping && schedule.isEmpty() && inFlight == 0) {
                    break;
                }

                // new events, paced to the rate
                while (now >= nextSendAt
                        && !schedule.isEmpty()
                        && schedule.peek().atNanos() <= now) {
                    if (!hasFreeId(ports)) {
                        break; // too many in flight; wait for responses or timeouts
                    }
                    Due d = schedule.poll();
                    Request r = newRequest(d);
                    r.server = nextServer;
                    nextServer = (nextServer + 1) % settings.servers().size();
                    if (!stopping && d.status() != 2) {
                        schedule.add(new Due(
                                d.atNanos() + interimNanos,
                                d.session(),
                                3,
                                d.sessionTime() + settings.interim().toSeconds()));
                    }
                    send(r, ports, now);
                    sent++;
                    inFlight++;
                    nextSendAt += gapNanos;
                    if (nextSendAt < now - gapNanos * 10) {
                        nextSendAt = now; // do not burst after a stall
                    }
                }

                // responses
                selector.select(1);
                for (SelectionKey key : selector.selectedKeys()) {
                    Port port = (Port) key.attachment();
                    while (true) {
                        receive.clear();
                        if (port.channel.receive(receive) == null) {
                            break;
                        }
                        Request r = matchResponse(port, receive.position());
                        if (r != null) {
                            long latency = (System.nanoTime() - r.firstSentNanos) / 1000;
                            latencies.add(latency);
                            acked++;
                            inFlight--;
                            record(log, r, true, latency);
                        }
                    }
                }
                selector.selectedKeys().clear();

                // timeouts: retransmit the identical datagram (same port, Identifier and authenticator) like a NAS
                now = System.nanoTime();
                for (Port port : ports) {
                    for (int id = 0; id < IDS_PER_CHANNEL; id++) {
                        Request r = port.inFlight[id];
                        if (r != null && now > r.deadlineNanos) {
                            if (r.attempts <= settings.retries()) {
                                if (settings.retryOtherServer()) {
                                    r.server =
                                            (r.server + 1) % settings.servers().size();
                                }
                                r.attempts++;
                                r.deadlineNanos = now + settings.timeout().toNanos();
                                send(port, r.bytes, settings.servers().get(r.server));
                                retransmissions++;
                            } else {
                                port.inFlight[id] = null;
                                port.freeIds.add(id);
                                failed++;
                                inFlight--;
                                record(log, r, false, 0);
                            }
                        }
                    }
                }
            }
            for (Port port : ports) {
                port.channel.close();
            }
        }
        double seconds = (System.nanoTime() - start) / 1e9;
        long[] sorted = latencies.stream().mapToLong(Long::longValue).sorted().toArray();
        Result result = new Result(
                sent,
                acked,
                failed,
                retransmissions,
                percentile(sorted, 50),
                percentile(sorted, 99),
                sorted.length == 0 ? 0 : sorted[sorted.length - 1],
                seconds);
        out.printf(
                "load: sent %d, acked %d, failed %d, retransmissions %d in %.1fs (%.0f req/s); latency p50 %.1f ms, p99 %.1f ms, max %.1f ms%n",
                result.sent(),
                result.acked(),
                result.failed(),
                result.retransmissions(),
                seconds,
                result.acked() / seconds,
                result.p50Micros() / 1000.0,
                result.p99Micros() / 1000.0,
                result.maxMicros() / 1000.0);
        if (sendStalls > 0 || sendDropped > 0) {
            out.printf("load: socket buffer full %d times, %d datagrams not sent%n", sendStalls, sendDropped);
        }
        if (unmatched > 0) {
            out.printf(
                    "load: %d responses matched no request in flight (late, duplicate or not authentic)%n", unmatched);
        }
        return result;
    }

    private static List<Due> drainLatest(PriorityQueue<Due> schedule) {
        // the latest scheduled event of every session that is still active
        List<Due> all = new ArrayList<>(schedule);
        schedule.clear();
        java.util.Map<Integer, Due> latest = new java.util.TreeMap<>();
        for (Due d : all) {
            latest.merge(d.session(), d, (a, b) -> a.sessionTime() >= b.sessionTime() ? a : b);
        }
        List<Due> result = new ArrayList<>();
        for (Due d : latest.values()) {
            // a session whose Start is still pending has not started: just drop it
            if (d.status() != 1) {
                result.add(new Due(d.atNanos(), d.session(), d.status(), d.sessionTime()));
            }
        }
        return result;
    }

    private Request newRequest(Due d) {
        Request r = new Request();
        int session = settings.firstSession() + d.session();
        int nasIndex = session % settings.nas();
        r.device = "nas" + nasIndex;
        r.sessionId = settings.sharedSessionIds()
                ? String.format("%08X", session / settings.nas())
                : r.device + "-" + session;
        r.status = d.status();
        r.sessionTime = d.sessionTime();
        return r;
    }

    private static boolean hasFreeId(List<Port> ports) {
        for (Port p : ports) {
            if (!p.freeIds.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private void send(Request r, List<Port> ports, long now) throws IOException {
        Port port = null;
        int base = random.nextInt(ports.size());
        for (int i = 0; i < ports.size() && port == null; i++) {
            Port candidate = ports.get((base + i) % ports.size());
            if (!candidate.freeIds.isEmpty()) {
                port = candidate;
            }
        }
        int id = port.freeIds.poll();
        r.bytes = encode(r, id);
        r.identifier = id;
        port.inFlight[id] = r;
        r.firstSentNanos = now;
        r.attempts = 1;
        r.deadlineNanos = now + settings.timeout().toNanos();
        send(port, r.bytes, settings.servers().get(r.server));
    }

    /**
     * The address to bind the ports to: loopback when every server is local, otherwise the wildcard. A specific
     * bind matters on a shared host: other programs binding {@code 127.0.0.1:0} with address reuse (Aeron does)
     * can otherwise be given a port this generator holds on the wildcard address and take its responses (seen
     * in the in-JVM tests: whole ports of 256 requests lost).
     */
    private java.net.InetAddress localAddress() {
        boolean loopback = settings.servers().stream()
                .allMatch(s -> s.getAddress() != null && s.getAddress().isLoopbackAddress());
        return loopback ? java.net.InetAddress.getLoopbackAddress() : null;
    }

    /**
     * A non-blocking send returns 0 when the socket buffer is momentarily full and the datagram is then not sent
     * at all; retry briefly instead of losing it, and count what still could not be sent.
     */
    private void send(Port port, byte[] bytes, InetSocketAddress server) throws IOException {
        ByteBuffer datagram = ByteBuffer.wrap(bytes);
        for (int attempt = 0; attempt < 1000; attempt++) {
            if (port.channel.send(datagram, server) > 0) {
                return;
            }
            sendStalls++;
            java.util.concurrent.locks.LockSupport.parkNanos(50_000);
        }
        sendDropped++;
    }

    private byte[] encode(Request r, int identifier) {
        long octets = r.sessionTime * 125_000L; // ~1 Mbit/s
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, identifier)
                .uint32(40, r.status)
                .attribute(44, r.sessionId)
                .attribute(1, r.sessionId + "@load.example")
                .attribute(32, r.device)
                .ipv4(4, 0x7F000001L)
                .uint32(55, 1_780_000_000L + r.sessionTime);
        if (r.status != 1) {
            encoder.uint32(46, r.sessionTime).uint32(42, octets & 0xFFFF_FFFFL).uint32(43, (octets * 4) & 0xFFFF_FFFFL);
        }
        int length = encoder.finish();
        authenticator.signAccountingRequest(buffer, 0, length, -1, settings.secret());
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    private Request matchResponse(Port port, int length) {
        if (responseView.wrap(new UnsafeBuffer(receive.array(), 0, length), 0, length) != DecodeStatus.OK
                || responseView.code() != RadiusCode.ACCOUNTING_RESPONSE) {
            unmatched++;
            return null;
        }
        int id = responseView.identifier();
        Request r = port.inFlight[id];
        if (r == null || !authenticator.verifyResponse(responseView, new UnsafeBuffer(r.bytes), 4, settings.secret())) {
            unmatched++;
            return null;
        }
        port.inFlight[id] = null;
        port.freeIds.add(id);
        return r;
    }

    private static void record(BufferedWriter log, Request r, boolean acked, long latencyMicros) throws IOException {
        if (log != null) {
            log.write(r.sessionId + "," + r.status + "," + r.sessionTime + "," + (acked ? 1 : 0) + "," + r.attempts
                    + "," + String.format("%.3f", latencyMicros / 1000.0) + "," + r.device + "\n");
        }
    }

    private static long percentile(long[] sorted, int p) {
        if (sorted.length == 0) {
            return 0;
        }
        return sorted[Math.min(sorted.length - 1, (int) Math.ceil(p / 100.0 * sorted.length) - 1)];
    }
}
