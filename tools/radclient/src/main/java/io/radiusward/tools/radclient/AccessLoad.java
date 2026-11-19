/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import static io.radiusward.radius.codec.attributes.Ietf.NAS_IDENTIFIER;
import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;

import io.radiusward.client.Credentials;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.time.Duration;
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
            List<Credentials.Method> methods,
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

    private final Settings settings;
    private final PrintStream out;
    private final Random random = new java.security.SecureRandom(); // request authenticators must not be predictable
    private final Credentials credentials = new Credentials(random);
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);

    private static final class Request extends RequestPorts.Outstanding {
        /** Which request it is: its user and method go round-robin. */
        long number;

        boolean wrongPassword;
    }

    private long accepted;
    private long rejected;
    private long challenged;
    private long timeouts;
    private long unexpected;
    private final List<Long> latencies = new ArrayList<>();

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
        long wrong = 0;
        int nextServer = 0;
        try (RequestPorts<Request> ports = new RequestPorts<>(
                RequestPorts.portsFor(settings.rate(), settings.timeout(), 1),
                settings.servers(),
                settings.secret(),
                settings.timeout(),
                settings.retries(),
                false,
                code -> true, // Accept, Reject and Challenge are all answers
                random,
                Request[]::new)) {
            while (true) {
                long now = System.nanoTime();
                if (now >= end && ports.inFlight() == 0) {
                    break;
                }
                while (now < end && now >= nextSendAt && ports.hasFree()) {
                    Request r = new Request();
                    r.number = sent;
                    r.wrongPassword = random.nextDouble() < settings.rejectRatio();
                    r.server = nextServer;
                    nextServer = (nextServer + 1) % settings.servers().size();
                    ports.send(r, now, (q, id) -> encode(id, q.number, q.wrongPassword));
                    sent++;
                    wrong += r.wrongPassword ? 1 : 0;
                    nextSendAt += gapNanos;
                    if (nextSendAt < now - RequestPorts.CATCH_UP_NANOS) {
                        nextSendAt = now; // a longer stall is lost rather than sent as one burst
                    }
                }
                ports.receive(this::answered);
                ports.expire(System.nanoTime(), r -> timeouts++);
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
                RequestPort.percentile(sorted, 50),
                RequestPort.percentile(sorted, 99));
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

    private void answered(Request r, RadiusPacket answer, long latencyMicros) {
        latencies.add(latencyMicros);
        switch (answer.code()) {
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

    /** Request {@code n}: its user and method round-robin, the password wrong when the request is meant to fail. */
    private byte[] encode(int identifier, long n, boolean wrong) {
        String user = settings.users().get((int) (n % settings.users().size()));
        Credentials.Method method =
                settings.methods().get((int) (n % settings.methods().size()));
        byte[] requestAuthenticator = new byte[16];
        random.nextBytes(requestAuthenticator);
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, identifier)
                .authenticator(requestAuthenticator)
                .attribute(USER_NAME, user)
                .ipv4(4, 0x7F000001L)
                .attribute(NAS_IDENTIFIER, "load");
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
}
