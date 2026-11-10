/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
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
        UnsafeBuffer out = new UnsafeBuffer(new byte[64]);
        out.putByte(0, (byte) code);
        out.putByte(1, r.bytes()[1]);
        int length = 20;
        if (errorCause != 0) {
            out.putByte(20, (byte) DynamicAuthorization.ERROR_CAUSE);
            out.putByte(21, (byte) 6);
            out.putInt(22, errorCause, java.nio.ByteOrder.BIG_ENDIAN);
            length = 26;
        }
        out.putShort(2, (short) length, java.nio.ByteOrder.BIG_ENDIAN);
        authenticator.signResponse(out, 0, length, -1, new UnsafeBuffer(r.bytes()), 4, secret);
        nas.send(ByteBuffer.wrap(out.byteArray(), 0, length), r.from());
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
}
