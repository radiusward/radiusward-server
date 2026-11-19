/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.client.PacketBuilder;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.attributes.Ietf;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Disconnect- and CoA-Requests against a fake NAS on a UDP socket (RFC 5176, ADR 0036). */
class DynamicAuthorizationTest {

    static final byte[] SECRET = "coa-secret".getBytes(StandardCharsets.US_ASCII);
    static final byte[] IDENTITY = {44, 6, 'a', 'b', 'c', 'd', 1, 7, 'a', 'l', 'i', 'c', 'e'};

    private DynamicAuthorization sender;
    private DatagramChannel nas;
    private InetSocketAddress nasAddress;
    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();

    @BeforeEach
    void start() throws Exception {
        sender = new DynamicAuthorization(
                new CoaConfig(true, Duration.ofMillis(50), 2, null, Map.of()), "127.0.0.1", null);
        sender.onStart();
        nas = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        nas.configureBlocking(false);
        nasAddress = (InetSocketAddress) nas.getLocalAddress();
    }

    @AfterEach
    void stop() throws Exception {
        sender.onClose();
        nas.close();
    }

    /** The next request at the fake NAS, checked like a NAS checks it; {@code null} if none came. */
    private Received receive() throws Exception {
        ByteBuffer in = ByteBuffer.allocate(4096);
        for (int i = 0; i < 100; i++) {
            sender.doWork();
            in.clear();
            InetSocketAddress from = (InetSocketAddress) nas.receive(in);
            if (from != null) {
                byte[] bytes = Arrays.copyOf(in.array(), in.position());
                RadiusPacket p = new RadiusPacket();
                p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
                assertThat(authenticator.verifyAccountingRequest(p, SECRET))
                        .as("Request Authenticator")
                        .isTrue();
                assertThat(authenticator.verifyRequestMessageAuthenticator(p, SECRET))
                        .as("Message-Authenticator")
                        .isTrue();
                return new Received(bytes, from);
            }
            Thread.sleep(2);
        }
        return null;
    }

    record Received(byte[] bytes, InetSocketAddress from) {}

    /** Answers like a NAS: code, optional Error-Cause, signed with the request's authenticator. */
    private void answer(Received r, int code, int errorCause, byte[] secret) throws Exception {
        PacketBuilder reply = PacketBuilder.reply(code, r.bytes());
        if (errorCause != 0) {
            reply.uint32(Ietf.ERROR_CAUSE, errorCause);
        }
        nas.send(ByteBuffer.wrap(reply.secret(secret).build()), r.from());
    }

    private DynamicAuthorization.Result await(CompletableFuture<DynamicAuthorization.Result> f) throws Exception {
        for (int i = 0; i < 500 && !f.isDone(); i++) {
            sender.doWork();
            Thread.sleep(2);
        }
        return f.getNow(null);
    }

    @Test
    void disconnectAcknowledged() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        Received r = receive();
        assertThat(r.bytes()[0]).isEqualTo((byte) DynamicAuthorization.DISCONNECT_REQUEST);
        assertThat(new String(r.bytes(), StandardCharsets.ISO_8859_1))
                .contains("abcd")
                .contains("alice");
        answer(r, DynamicAuthorization.DISCONNECT_ACK, 0, SECRET);
        assertThat(await(f)).isEqualTo(new DynamicAuthorization.Result(DynamicAuthorization.Outcome.ACK, 0));
        assertThat(sender.get(DynamicAuthorization.Counter.ACK)).isEqualTo(1);
    }

    @Test
    void coaRefusedWithItsErrorCause() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.COA_REQUEST, IDENTITY, nasAddress, SECRET);
        Received r = receive();
        answer(r, DynamicAuthorization.COA_NAK, 503, SECRET); // Session Context Not Found
        assertThat(await(f)).isEqualTo(new DynamicAuthorization.Result(DynamicAuthorization.Outcome.NAK, 503));
    }

    @Test
    void resentThenGivenUpAndForgedAnswersIgnored() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        Received first = receive();
        answer(first, DynamicAuthorization.DISCONNECT_ACK, 0, "wrong".getBytes(StandardCharsets.US_ASCII));
        Received again = receive();
        assertThat(again).as("resent: the forged ACK did not count").isNotNull();
        assertThat(again.bytes()[1]).as("same identifier").isEqualTo(first.bytes()[1]);
        assertThat(receive()).as("second retry").isNotNull();
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.TIMEOUT);
        assertThat(sender.get(DynamicAuthorization.Counter.RESENT)).isEqualTo(2);
        assertThat(sender.get(DynamicAuthorization.Counter.INVALID_RESPONSES)).isEqualTo(1);
    }

    @Test
    void requestsInFlightToOneNasGetTheirOwnIdentifiers() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> a =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        CompletableFuture<DynamicAuthorization.Result> b =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        Received ra = receive();
        Received rb = receive();
        assertThat(ra.bytes()[1]).isNotEqualTo(rb.bytes()[1]);
        answer(rb, DynamicAuthorization.DISCONNECT_ACK, 0, SECRET);
        answer(ra, DynamicAuthorization.DISCONNECT_NAK, 0, SECRET);
        assertThat(await(a).outcome()).isEqualTo(DynamicAuthorization.Outcome.NAK);
        assertThat(await(b).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void aRequestTooLargeForOnePacketIsUnreachable() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.COA_REQUEST, new byte[4096 - 20 - 17], nasAddress, SECRET);
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.UNREACHABLE);
        assertThat(sender.get(DynamicAuthorization.Counter.UNREACHABLE)).isEqualTo(1);
        assertThat(receive()).isNull();
    }

    @Test
    void the257thRequestInFlightToOneNasIsUnreachable() throws Exception {
        java.util.List<CompletableFuture<DynamicAuthorization.Result>> all = new java.util.ArrayList<>();
        for (int i = 0; i < 257; i++) {
            all.add(sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET));
        }
        sender.doWork();
        assertThat(all.get(256).getNow(null))
                .isEqualTo(new DynamicAuthorization.Result(DynamicAuthorization.Outcome.UNREACHABLE, 0));
        assertThat(all.subList(0, 256)).noneMatch(CompletableFuture::isDone);
    }

    @Test
    void malformedLateAndWrongCodeAnswersAreCountedAsInvalid() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        Received r = receive();
        nas.send(ByteBuffer.wrap(new byte[] {41, 0, 0}), r.from()); // shorter than a header
        answer(r, 2, 0, SECRET); // Access-Accept: not an answer to a Disconnect-Request
        byte[] stray = r.bytes().clone();
        stray[1]++; // an identifier nothing waits for
        answer(new Received(stray, r.from()), DynamicAuthorization.DISCONNECT_ACK, 0, SECRET);
        for (int i = 0; i < 20; i++) {
            sender.doWork();
            Thread.sleep(2);
        }
        assertThat(sender.get(DynamicAuthorization.Counter.INVALID_RESPONSES)).isEqualTo(3);
        answer(r, DynamicAuthorization.DISCONNECT_ACK, 0, SECRET);
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void anErrorCauseOfTheWrongLengthIsIgnored() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.COA_REQUEST, IDENTITY, nasAddress, SECRET);
        Received r = receive();
        byte[] shortErrorCause = {(byte) Ietf.ERROR_CAUSE, 4, 503 >> 8, (byte) 503}; // two octets, not four
        nas.send(
                ByteBuffer.wrap(PacketBuilder.reply(DynamicAuthorization.COA_NAK, r.bytes())
                        .raw(shortErrorCause)
                        .secret(SECRET)
                        .build()),
                r.from());
        assertThat(await(f)).isEqualTo(new DynamicAuthorization.Result(DynamicAuthorization.Outcome.NAK, 0));
    }

    @Test
    void overRadsecTheRequestGoesToTheNasConnectionAndItsAnswerComesBack() throws Exception {
        sender.onClose();
        RadsecLink link = new RadsecLink(new NasClient[] {
            NasClient.builder("ap", 1)
                    .network(0x7F000001, 32)
                    .secret(SECRET)
                    .messageAuthenticator(NasClient.MessageAuthenticatorPolicy.OFF)
                    .build()
        });
        sender = new DynamicAuthorization(
                new CoaConfig(true, Duration.ofMillis(50), 2, null, Map.of()), "127.0.0.1", link);
        sender.onStart();
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.sendRadsec(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, 0, SECRET);
        sender.doWork();
        byte[][] request = new byte[1][];
        int[] nasIndex = {-1};
        link.toNas.read((type, buffer, index, length) -> {
            nasIndex[0] = buffer.getInt(index);
            request[0] = new byte[length - 4];
            buffer.getBytes(index + 4, request[0]);
        });
        assertThat(nasIndex[0]).isZero();
        assertThat(request[0][0]).isEqualTo((byte) DynamicAuthorization.DISCONNECT_REQUEST);

        byte[] ack = PacketBuilder.reply(DynamicAuthorization.DISCONNECT_ACK, request[0])
                .secret(SECRET)
                .build();
        UnsafeBuffer reply = new UnsafeBuffer(new byte[4 + ack.length]); // the link's index, then the packet
        reply.putBytes(4, ack);
        assertThat(link.fromNas.write(RadsecLink.PACKET_MSG, reply, 0, reply.capacity()))
                .isTrue();
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void closingTimesOutRequestsInFlightAndRefusesQueuedOnes() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> inFlight =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        sender.doWork();
        CompletableFuture<DynamicAuthorization.Result> queued =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        sender.onClose();
        assertThat(inFlight.getNow(null).outcome()).isEqualTo(DynamicAuthorization.Outcome.TIMEOUT);
        assertThat(queued.getNow(null).outcome()).isEqualTo(DynamicAuthorization.Outcome.UNREACHABLE);
    }

    @Test
    void metricsCountEveryOutcome() throws Exception {
        CompletableFuture<DynamicAuthorization.Result> f =
                sender.send(DynamicAuthorization.DISCONNECT_REQUEST, IDENTITY, nasAddress, SECRET);
        answer(receive(), DynamicAuthorization.DISCONNECT_ACK, 0, SECRET);
        await(f);
        io.radiusward.common.management.PrometheusWriter w = new io.radiusward.common.management.PrometheusWriter();
        sender.writeMetrics(w, "g1");
        String text = w.finish();
        io.radiusward.common.management.PrometheusWriter.validate(text);
        assertThat(text)
                .contains("radiusward_server_coa_requests_total{server=\"g1\",result=\"sent\"} 1")
                .contains("radiusward_server_coa_requests_total{server=\"g1\",result=\"ack\"} 1")
                .contains("radiusward_server_coa_requests_total{server=\"g1\",result=\"timeout\"} 0");
    }
}
