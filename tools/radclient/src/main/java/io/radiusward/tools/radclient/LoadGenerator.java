/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import static io.radiusward.radius.codec.attributes.Ietf.ACCT_SESSION_ID;
import static io.radiusward.radius.codec.attributes.Ietf.NAS_IDENTIFIER;
import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
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
 * <p>All simulated NAS share this machine's address, so the RADIUS server sees one NAS entry, like access points behind
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

        /** Settings for these servers and shared secret, every other value at its default. */
        public static Builder builder(List<InetSocketAddress> servers, byte[] secret) {
            return new Builder(servers, secret);
        }

        public static final class Builder {
            private final List<InetSocketAddress> servers;
            private final byte[] secret;
            private int nas = 1;
            private int sessions = 100;
            private int rate = 100;
            private Duration duration = Duration.ofSeconds(10);
            private Duration interim = Duration.ofSeconds(60);
            private Duration timeout = Duration.ofSeconds(1);
            private int retries = 3;
            private boolean retryOtherServer = false;
            private boolean stopAtEnd = false;
            private Path ackLog = null;
            private int firstSession = 0;
            private boolean sharedSessionIds = false;

            private Builder(List<InetSocketAddress> servers, byte[] secret) {
                this.servers = servers;
                this.secret = secret;
            }

            /** Simulated NAS (NAS-Identifier {@code nas<n>}); default 1. */
            public Builder nas(int nas) {
                this.nas = nas;
                return this;
            }

            /** Sessions per NAS; default 100. */
            public Builder sessions(int sessions) {
                this.sessions = sessions;
                return this;
            }

            /** Requests per second; default 100. */
            public Builder rate(int rate) {
                this.rate = rate;
                return this;
            }

            /** How long to send; default 10s. */
            public Builder duration(Duration duration) {
                this.duration = duration;
                return this;
            }

            /** Interim interval of each session; default 60s. */
            public Builder interim(Duration interim) {
                this.interim = interim;
                return this;
            }

            /** Per attempt; default 1s. */
            public Builder timeout(Duration timeout) {
                this.timeout = timeout;
                return this;
            }

            /** Retransmissions of a request; default 3. */
            public Builder retries(int retries) {
                this.retries = retries;
                return this;
            }

            /** A retransmission goes to the next server; default false. */
            public Builder retryOtherServer(boolean retryOtherServer) {
                this.retryOtherServer = retryOtherServer;
                return this;
            }

            /** Stop every session at the end; default false. */
            public Builder stopAtEnd(boolean stopAtEnd) {
                this.stopAtEnd = stopAtEnd;
                return this;
            }

            /** Acknowledged events as CSV ({@code null}: none); default null. */
            public Builder ackLog(Path ackLog) {
                this.ackLog = ackLog;
                return this;
            }

            /** Number of the first session (several generators side by side); default 0. */
            public Builder firstSession(int firstSession) {
                this.firstSession = firstSession;
                return this;
            }

            /** Session ids repeat across the NAS (devices numbering from boot); default false. */
            public Builder sharedSessionIds(boolean sharedSessionIds) {
                this.sharedSessionIds = sharedSessionIds;
                return this;
            }

            public Settings build() {
                return new Settings(
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
                        sharedSessionIds);
            }
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

    private final Settings settings;
    private final PrintStream out;
    private final Random random = new Random(42);
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private long acked;
    private long failed;
    private final List<Long> latencies = new ArrayList<>();

    /** One request in flight. */
    private static final class Request extends RequestPorts.Outstanding {
        String device;
        String sessionId;
        int status;
        long sessionTime;
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

        long sent = 0;
        int nextServer = 0;
        long nextSendAt = start;
        long retransmissions;
        long unmatched;
        long sendStalls;
        long sendDropped;

        try (BufferedWriter log = settings.ackLog() == null
                        ? null
                        : Files.newBufferedWriter(settings.ackLog(), StandardCharsets.UTF_8);
                RequestPorts<Request> ports = new RequestPorts<>(
                        RequestPorts.portsFor(settings.rate(), settings.timeout(), 2),
                        settings.servers(),
                        settings.secret(),
                        settings.timeout(),
                        settings.retries(),
                        settings.retryOtherServer(),
                        code -> code == RadiusCode.ACCOUNTING_RESPONSE,
                        random,
                        Request[]::new)) {
            if (log != null) {
                log.write("session_id,status,session_time,acked,attempts,latency_ms,nas_identifier\n");
            }
            boolean stopping = false;
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
                if (stopping && schedule.isEmpty() && ports.inFlight() == 0) {
                    break;
                }

                // new events, paced to the rate
                while (now >= nextSendAt
                        && !schedule.isEmpty()
                        && schedule.peek().atNanos() <= now
                        && ports.hasFree()) {
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
                    ports.send(r, now, this::encode);
                    sent++;
                    nextSendAt += gapNanos;
                    if (nextSendAt < now - RequestPorts.CATCH_UP_NANOS) {
                        nextSendAt = now; // a longer stall is lost rather than sent as one burst
                    }
                }

                ports.receive((r, answer, latency) -> {
                    latencies.add(latency);
                    acked++;
                    record(log, r, true, latency);
                });
                ports.expire(System.nanoTime(), r -> {
                    failed++;
                    record(log, r, false, 0);
                });
            }
            retransmissions = ports.retransmissions();
            unmatched = ports.unmatched();
            sendStalls = ports.sendStalls();
            sendDropped = ports.sendDropped();
        }
        double seconds = (System.nanoTime() - start) / 1e9;
        long[] sorted = latencies.stream().mapToLong(Long::longValue).sorted().toArray();
        Result result = new Result(
                sent,
                acked,
                failed,
                retransmissions,
                RequestPort.percentile(sorted, 50),
                RequestPort.percentile(sorted, 99),
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

    private byte[] encode(Request r, int identifier) {
        long octets = r.sessionTime * 125_000L; // ~1 Mbit/s
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, identifier)
                .uint32(40, r.status)
                .attribute(ACCT_SESSION_ID, r.sessionId)
                .attribute(USER_NAME, r.sessionId + "@load.example")
                .attribute(NAS_IDENTIFIER, r.device)
                .ipv4(4, 0x7F000001L)
                .uint32(55, 1_780_000_000L + r.sessionTime);
        if (r.status != 1) {
            encoder.uint32(46, r.sessionTime).uint32(42, octets & 0xFFFF_FFFFL).uint32(43, (octets * 4) & 0xFFFF_FFFFL);
        }
        int length = encoder.finish();
        authenticator.signAccountingRequest(buffer, 0, length, -1, settings.secret());
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    private static void record(BufferedWriter log, Request r, boolean acked, long latencyMicros) throws IOException {
        if (log != null) {
            log.write(r.sessionId + "," + r.status + "," + r.sessionTime + "," + (acked ? 1 : 0) + "," + r.attempts
                    + "," + String.format("%.3f", latencyMicros / 1000.0) + "," + r.device + "\n");
        }
    }
}
