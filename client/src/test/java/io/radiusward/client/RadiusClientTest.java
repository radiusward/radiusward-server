/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class RadiusClientTest {

    private static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);

    /** A RADIUS server on loopback that answers each datagram with what {@code answer} returns (null: silence). */
    private static final class Server implements AutoCloseable {
        final DatagramSocket socket;
        final List<byte[]> received = new ArrayList<>();
        final Thread thread;

        Server(Function<byte[], byte[]> answer) throws Exception {
            socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
            thread = Thread.ofVirtual().start(() -> {
                byte[] buffer = new byte[RadiusPacket.MAX_LENGTH];
                while (!socket.isClosed()) {
                    try {
                        DatagramPacket in = new DatagramPacket(buffer, buffer.length);
                        socket.receive(in);
                        byte[] request = Arrays.copyOf(in.getData(), in.getLength());
                        synchronized (received) {
                            received.add(request);
                        }
                        byte[] out = answer.apply(request);
                        if (out != null) {
                            socket.send(new DatagramPacket(out, out.length, in.getSocketAddress()));
                        }
                    } catch (Exception e) {
                        return; // closed
                    }
                }
            });
        }

        int port() {
            return socket.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            socket.close();
            thread.join(2000);
        }
    }

    private Server server;
    private RadiusClient client;

    @AfterEach
    void stop() throws Exception {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
    }

    private RadiusClient client(Function<byte[], byte[]> answer) throws Exception {
        server = new Server(answer);
        client = RadiusClient.udp(InetAddress.getLoopbackAddress().getHostAddress(), server.port(), "testing123")
                .timeout(Duration.ofMillis(300))
                .retries(2);
        return client;
    }

    private static RadiusPacket wrap(byte[] bytes) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return p;
    }

    private static byte[] answer(byte[] request, boolean accepted) {
        return PacketBuilder.reply(accepted ? RadiusCode.ACCESS_ACCEPT : RadiusCode.ACCESS_REJECT, request)
                .messageAuthenticator()
                .secret(SECRET)
                .build();
    }

    @Test
    void papIsHiddenWithTheSecretAndAcceptedWhenTheServerReadsItBack() throws Exception {
        RadiusClient c = client(request -> {
            RadiusPacket p = wrap(request);
            UnsafeBuffer plain = new UnsafeBuffer(new byte[128]);
            int n = new AccessRequests().decryptUserPassword(p, SECRET, plain, 0);
            boolean ok = new RadiusAuthenticator().verifyRequestMessageAuthenticator(p, SECRET)
                    && "alice".equals(p.string(1))
                    && n > 0
                    && plain.getStringWithoutLengthUtf8(0, n).equals("secret");
            return answer(request, ok);
        });
        assertThat(c.pap("alice", "secret").orElseThrow().isAccept()).isTrue();
        assertThat(c.pap("alice", "wrong").orElseThrow().isReject()).isTrue();
    }

    @Test
    void chapAndMsChapV2CarryWhatTheServerChecks() throws Exception {
        RadiusClient c = client(request -> {
            RadiusPacket p = wrap(request);
            byte[] password = "secret".getBytes(StandardCharsets.UTF_8);
            boolean ok;
            if (p.findAttribute(AccessRequests.CHAP_PASSWORD) >= 0) {
                ok = new AccessRequests().verifyChap(p, new UnsafeBuffer(password), 0, password.length) > 0;
            } else {
                AttributeCursor cursor = new AttributeCursor().wrap(p);
                byte[] challenge = null;
                byte[] response = null;
                while (cursor.next()) {
                    byte[] v = new byte[cursor.valueLength()];
                    cursor.buffer().getBytes(cursor.valueOffset(), v);
                    if (cursor.vendorId() == AccessRequests.MICROSOFT && cursor.type() == 11) {
                        challenge = v;
                    } else if (cursor.vendorId() == AccessRequests.MICROSOFT && cursor.type() == 25) {
                        response = v;
                    }
                }
                ok = challenge != null
                        && response != null
                        && Arrays.equals(
                                Arrays.copyOfRange(response, 26, 50),
                                Credentials.ntResponse(
                                        challenge, Arrays.copyOfRange(response, 2, 18), "bob", "secret"));
            }
            return answer(request, ok);
        });
        assertThat(c.chap("bob", "secret").orElseThrow().isAccept()).isTrue();
        assertThat(c.chap("bob", "wrong").orElseThrow().isReject()).isTrue();
        assertThat(c.msChapV2("bob", "secret").orElseThrow().isAccept()).isTrue();
        assertThat(c.msChapV2("bob", "wrong").orElseThrow().isReject()).isTrue();
    }

    @Test
    void anUnansweredRequestIsSentAgainUnchanged() throws Exception {
        int[] seen = {0};
        RadiusClient c = client(request -> ++seen[0] == 1 ? null : answer(request, true));
        Response r = c.pap("alice", "secret").orElseThrow();
        assertThat(r.attempts()).isEqualTo(2);
        assertThat(r.elapsed()).isGreaterThanOrEqualTo(Duration.ofMillis(300));
        assertThat(server.received).hasSize(2);
        assertThat(server.received.get(1))
                .as("a retransmission, not a new request")
                .isEqualTo(server.received.get(0));
    }

    @Test
    void answersThatDoNotVerifyAreIgnoredLikeANasIgnoresThem() throws Exception {
        RadiusClient c = client(request -> PacketBuilder.reply(RadiusCode.ACCESS_ACCEPT, request)
                .secret("not-the-secret")
                .build());
        assertThat(c.pap("alice", "secret")).as("a forged Accept").isEmpty();
        assertThat(server.received).as("every attempt sent").hasSize(3);
    }

    @Test
    void aLateAnswerToAnotherRequestIsNotTakenForThisOne() throws Exception {
        byte[][] previous = {null};
        RadiusClient c = client(request -> {
            byte[] late = previous[0];
            previous[0] = request;
            return late == null ? null : answer(late, true); // always the answer to the request before
        });
        c.retries(0);
        assertThat(c.pap("alice", "secret")).isEmpty();
        assertThat(c.pap("alice", "secret")).as("the first one's late answer").isEmpty();
    }

    @Test
    void accountingAndStatusServerAreAcknowledged() throws Exception {
        RadiusClient c = client(request -> {
            RadiusPacket p = wrap(request);
            int code = p.code() == RadiusCode.ACCOUNTING_REQUEST
                    ? (new RadiusAuthenticator().verifyAccountingRequest(p, SECRET)
                            ? RadiusCode.ACCOUNTING_RESPONSE
                            : 0)
                    : RadiusCode.ACCESS_ACCEPT;
            return code == 0
                    ? null
                    : PacketBuilder.reply(code, request).secret(SECRET).build();
        });
        Response acct =
                c.send(c.accountingRequest().uint32(40, 1).attribute(44, "s-1")).orElseThrow();
        assertThat(acct.isAcknowledgement()).isTrue();
        assertThat(c.send(PacketBuilder.accountingRequest(c.nextIdentifier()).uint32(40, 2)))
                .as("a builder without a secret gets the client's")
                .hasValueSatisfying(r -> assertThat(r.isAcknowledgement()).isTrue());
        assertThat(c.statusServer())
                .hasValueSatisfying(r -> assertThat(r.isAccept()).isTrue());
    }

    @Test
    void theAnswersAttributesAreReadable() throws Exception {
        RadiusClient c = client(request -> PacketBuilder.reply(RadiusCode.ACCESS_ACCEPT, request)
                .attribute(25, "gold")
                .attribute(25, "vlan-10")
                .uint32(27, 3600)
                .attribute(18, "welcome")
                .vendor(311, 26, "S=00")
                .secret(SECRET)
                .build());
        Response r = c.pap("alice", "secret").orElseThrow();
        assertThat(r.string(25)).contains("gold");
        assertThat(r.all(25))
                .extracting(v -> new String(v, StandardCharsets.UTF_8))
                .containsExactly("gold", "vlan-10");
        assertThat(r.integer(27)).hasValue(3600);
        assertThat(r.integer(18)).as("not four bytes").isEmpty();
        assertThat(r.vendor(311, 26))
                .hasValueSatisfying(v -> assertThat(v).asString().isEqualTo("S=00"));
        assertThat(r.string(18)).contains("welcome");
        assertThat(r.string(11)).as("absent").isEmpty();
        assertThat(r.identifier()).isEqualTo(r.packet().identifier());
        assertThat(r.bytes()).hasSize(r.packet().length());
        assertThat(r.isChallenge()).isFalse();
    }

    @Test
    void identifiersGoRoundAndOptionsAreChecked() throws Exception {
        RadiusClient c = client(request -> null);
        assertThat(c.server().getPort()).isEqualTo(server.port());
        for (int i = 0; i < 255; i++) {
            c.nextIdentifier();
        }
        assertThat(c.nextIdentifier()).isEqualTo(255);
        assertThat(c.nextIdentifier()).isZero();
        assertThatThrownBy(() -> c.timeout(Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> c.retries(-1)).isInstanceOf(IllegalArgumentException.class);
    }
}
