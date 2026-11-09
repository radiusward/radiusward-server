/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The Access-Request path over real loopback UDP; the test drives the agent and the workers itself. */
class AuthAgentTest {

    static final byte[] SECRET = UdpAgentTest.SECRET;
    static final byte[] PASSWORD = "arctangent".getBytes(StandardCharsets.US_ASCII);

    private final long[] clock = {1_000_000_000L};
    private final AuthStats stats = new AuthStats();
    private final AtomicInteger decisions = new AtomicInteger();
    private AccessSlots slots;
    private AuthAgent agent;
    private AccessWorker worker;
    private DatagramChannel client;

    /** Accepts "arctangent" with Session-Timeout 3600, rejects anything else; "drop" and "fail" for errors. */
    final AccessHandler papHandler = context -> {
        decisions.incrementAndGet();
        UnsafeBuffer password = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
        int n = context.credentials()
                .decryptUserPassword(context.request(), context.nas().secret(), password, 0);
        String given = n < 0 ? "" : password.getStringWithoutLengthAscii(0, n);
        return switch (given) {
            case "arctangent" -> {
                context.reply().uint32(27, 3600);
                yield AccessHandler.ACCEPT;
            }
            case "drop" -> AccessHandler.DROP;
            case "fail" -> throw new IllegalStateException("store down");
            default -> AccessHandler.REJECT;
        };
    };

    void start(NasRegistry registry, int pending) throws Exception {
        slots = new AccessSlots(pending);
        agent = new AuthAgent(
                UdpAgentTest.config(Duration.ZERO, 1024),
                new AuthConfig(true, 0, 1, pending, 64, Duration.ofSeconds(10)),
                registry,
                slots,
                stats,
                () -> clock[0]);
        agent.onStart();
        worker = new AccessWorker(0, slots, papHandler, stats);
        client = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        client.configureBlocking(false);
        client.connect(new InetSocketAddress("127.0.0.1", agent.localPort()));
    }

    void start() throws Exception {
        start(registry(NasClient.MessageAuthenticatorPolicy.REQUIRED), 8);
    }

    static NasRegistry registry(NasClient.MessageAuthenticatorPolicy access) {
        return NasRegistry.of(List.of(new NasClient(
                "local",
                1001,
                0x7F000001,
                32,
                SECRET,
                "default",
                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                new NasClient.Identity[0],
                0,
                access)));
    }

    @AfterEach
    void stop() throws Exception {
        if (agent != null) {
            agent.onClose();
        }
        if (client != null) {
            client.close();
        }
    }

    /** A signed Access-Request: User-Password encrypted for {@code password}, a Proxy-State, optional MA / EAP. */
    static byte[] accessRequest(int identifier, String password, boolean withMa, boolean withEap) {
        byte[] authenticator = new byte[16];
        ThreadLocalRandom.current().nextBytes(authenticator);
        UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
        byte[] plain = password.getBytes(StandardCharsets.US_ASCII);
        int n = new AccessRequests()
                .encryptUserPassword(
                        new UnsafeBuffer(plain),
                        0,
                        plain.length,
                        new UnsafeBuffer(authenticator),
                        0,
                        SECRET,
                        cipher,
                        0);
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, identifier)
                .authenticator(authenticator)
                .attribute(1, "nemo")
                .attribute(2, cipher, 0, n)
                .attribute(33, "proxy-1");
        if (withEap) {
            enc.attribute(79, new byte[] {2, 1, 0, 5, 1});
        }
        int ma = withMa ? enc.messageAuthenticator() : -1;
        int length = enc.finish();
        if (ma >= 0) {
            new RadiusAuthenticator().signAccessRequest(buffer, 0, length, ma, SECRET);
        }
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    void send(byte[] packet) throws Exception {
        client.write(ByteBuffer.wrap(packet));
        work();
    }

    /** Lets the agent receive, the worker decide and the agent reply. */
    void work() throws Exception {
        for (int i = 0; i < 20; i++) {
            agent.doWork();
            worker.doWork();
            Thread.sleep(1);
        }
    }

    byte[] receive() throws Exception {
        ByteBuffer in = ByteBuffer.allocate(4096);
        int n = client.read(in);
        return n <= 0 ? null : Arrays.copyOf(in.array(), n);
    }

    static RadiusPacket wrap(byte[] bytes) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return p;
    }

    static void assertSignedReplyTo(byte[] reply, byte[] request, int code) {
        RadiusPacket r = wrap(reply);
        RadiusAuthenticator a = new RadiusAuthenticator();
        assertThat(r.code()).isEqualTo(code);
        assertThat(r.identifier()).isEqualTo(request[1] & 0xFF);
        assertThat(a.verifyResponse(r, new UnsafeBuffer(request), 4, SECRET)).isTrue();
        assertThat(a.verifyResponseMessageAuthenticator(r, new UnsafeBuffer(request), 4, SECRET))
                .isTrue();
        assertThat(reply[20]).as("Message-Authenticator first").isEqualTo((byte) 80);
        assertThat(r.findAttribute(33)).as("Proxy-State echoed").isPositive();
    }

    @Test
    void acceptAndRejectAreSignedRepliesFromTheSameSocket() throws Exception {
        start();
        byte[] good = accessRequest(1, "arctangent", true, false);
        send(good);
        byte[] accept = receive();
        assertSignedReplyTo(accept, good, RadiusCode.ACCESS_ACCEPT);
        assertThat(wrap(accept).findAttribute(27)).as("Session-Timeout").isPositive();

        byte[] bad = accessRequest(2, "wrong", true, false);
        send(bad);
        assertSignedReplyTo(receive(), bad, RadiusCode.ACCESS_REJECT);
        assertThat(stats.get(AuthStats.Counter.ACCEPTED)).isEqualTo(1);
        assertThat(stats.get(AuthStats.Counter.REJECTED)).isEqualTo(1);
        assertThat(stats.get(AuthStats.Counter.RESPONSES_SENT)).isEqualTo(2);
        assertThat(stats.inFlight()).isZero();
    }

    @Test
    void messageAuthenticatorIsRequiredByDefaultAndAlwaysWithEap() throws Exception {
        start();
        send(accessRequest(1, "arctangent", false, false));
        assertThat(receive()).isNull();
        assertThat(stats.get(AuthStats.Counter.MESSAGE_AUTHENTICATOR_MISSING)).isEqualTo(1);
        byte[] forged = accessRequest(2, "arctangent", true, false);
        forged[forged.length - 1] ^= 1; // last byte of the Message-Authenticator
        send(forged);
        assertThat(receive()).isNull();
        assertThat(stats.get(AuthStats.Counter.MESSAGE_AUTHENTICATOR_FAILED)).isEqualTo(1);
        assertThat(decisions).hasValue(0);
    }

    @Test
    void anEntryMayAllowRequestsWithoutMessageAuthenticatorButNotWithEap() throws Exception {
        start(registry(NasClient.MessageAuthenticatorPolicy.OFF), 8);
        byte[] plain = accessRequest(1, "arctangent", false, false);
        send(plain);
        assertSignedReplyTo(receive(), plain, RadiusCode.ACCESS_ACCEPT);
        send(accessRequest(2, "arctangent", false, true));
        assertThat(receive()).as("EAP without Message-Authenticator (RFC 3579)").isNull();
        assertThat(stats.get(AuthStats.Counter.MESSAGE_AUTHENTICATOR_MISSING)).isEqualTo(1);
    }

    @Test
    void retransmissionsAreDroppedWhileDecidedThenAnsweredFromTheCache() throws Exception {
        start();
        byte[] request = accessRequest(7, "arctangent", true, false);
        client.write(ByteBuffer.wrap(request));
        Thread.sleep(5);
        agent.doWork(); // queued for the worker, not decided yet
        client.write(ByteBuffer.wrap(request));
        Thread.sleep(5);
        agent.doWork();
        assertThat(stats.get(AuthStats.Counter.RETRANSMIT_IN_FLIGHT)).isEqualTo(1);
        work();
        byte[] first = receive();
        assertSignedReplyTo(first, request, RadiusCode.ACCESS_ACCEPT);

        send(request);
        assertThat(receive()).as("the same reply, byte for byte").isEqualTo(first);
        assertThat(stats.get(AuthStats.Counter.CACHE_HITS)).isEqualTo(1);
        assertThat(decisions).as("decided once").hasValue(1);

        clock[0] += Duration.ofSeconds(11).toNanos(); // past the reply cache TTL
        send(request);
        assertThat(receive()).isNotNull();
        assertThat(decisions).hasValue(2);
    }

    @Test
    void unansweredRequestsAreDecidedAgainOnRetransmission() throws Exception {
        start();
        byte[] drop = accessRequest(1, "drop", true, false);
        send(drop);
        assertThat(receive()).isNull();
        send(drop);
        assertThat(decisions).as("the store may be back").hasValue(2);
        send(accessRequest(2, "fail", true, false));
        assertThat(receive()).isNull();
        assertThat(stats.get(AuthStats.Counter.DROPPED)).isEqualTo(2);
        assertThat(stats.get(AuthStats.Counter.HANDLER_ERRORS)).isEqualTo(1);
        // the worker survived the exception
        byte[] good = accessRequest(3, "arctangent", true, false);
        send(good);
        assertSignedReplyTo(receive(), good, RadiusCode.ACCESS_ACCEPT);
    }

    @Test
    void fullSlotsDropInsteadOfQueueing() throws Exception {
        start(registry(NasClient.MessageAuthenticatorPolicy.REQUIRED), 2);
        for (int i = 1; i <= 3; i++) {
            client.write(ByteBuffer.wrap(accessRequest(i, "arctangent", true, false)));
        }
        Thread.sleep(5);
        agent.doWork(); // no worker runs: two slots taken, the third request has none
        assertThat(stats.get(AuthStats.Counter.BUSY)).isEqualTo(1);
        work();
        assertThat(stats.get(AuthStats.Counter.ACCEPTED)).isEqualTo(2);
    }

    @Test
    void otherPacketsAreCountedAndIgnored() throws Exception {
        start();
        send(new byte[] {1, 2, 3});
        send(UdpAgentTest.fixture("cisco", "start")); // an Accounting-Request on the auth port
        assertThat(stats.get(AuthStats.Counter.MALFORMED)).isEqualTo(1);
        assertThat(stats.get(AuthStats.Counter.NOT_ACCESS_REQUEST)).isEqualTo(1);
        assertThat(stats.get(AuthStats.Counter.RECEIVED)).isEqualTo(2);
        assertThat(receive()).isNull();
    }

    @Test
    void requestsFromUnknownAddressesAreIgnored() throws Exception {
        start(
                NasRegistry.of(List.of(new NasClient(
                        "elsewhere",
                        7,
                        0x0A090909,
                        32,
                        SECRET,
                        "default",
                        NasClient.MessageAuthenticatorPolicy.OPTIONAL))),
                8);
        send(accessRequest(1, "arctangent", true, false));
        assertThat(receive()).isNull();
        assertThat(stats.get(AuthStats.Counter.UNKNOWN_NAS)).isEqualTo(1);
        assertThat(decisions).hasValue(0);
    }
}
