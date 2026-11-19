/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.client.PacketBuilder;
import io.radiusward.radius.codec.RadiusCode;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.function.BooleanSupplier;
import java.util.function.IntFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The request ports against servers the test plays itself: identifiers, matching answers, retries, giving up. */
class RequestPortsTest {

    private static final byte[] SECRET = "s3cret".getBytes(StandardCharsets.US_ASCII);
    private static final long MS = 1_000_000L;

    private final List<Server> servers = new ArrayList<>();

    @AfterEach
    void closeServers() {
        servers.forEach(s -> s.socket.close());
    }

    @Test
    void whenEveryIdentifierIsTakenNothingCanBeSentUntilOneIsGivenUp() throws IOException {
        Server server = server();
        List<RequestPorts.Outstanding> gaveUp = new ArrayList<>();
        try (RequestPorts<RequestPorts.Outstanding> ports =
                ports(2, List.of(server), Duration.ofSeconds(1), 0, false)) {
            for (int i = 0; i < 2 * RequestPort.IDS; i++) {
                assertThat(ports.hasFree()).as("request %d", i).isTrue();
                ports.send(new RequestPorts.Outstanding(), 0, RequestPortsTest::accountingRequest);
            }
            assertThat(ports.inFlight()).isEqualTo(2 * RequestPort.IDS);
            assertThat(ports.hasFree()).isFalse();
            assertThatThrownBy(() -> ports.send(new RequestPorts.Outstanding(), 0, RequestPortsTest::accountingRequest))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("hasFree()");

            ports.expire(500 * MS, gaveUp::add);
            assertThat(gaveUp).as("not past the deadline yet").isEmpty();
            ports.expire(1_100 * MS, gaveUp::add); // no retries: past the deadline means given up
            assertThat(gaveUp).hasSize(2 * RequestPort.IDS);
            assertThat(ports.inFlight()).isZero();
            assertThat(ports.hasFree()).isTrue();
            assertThat(ports.retransmissions()).isZero();
            assertThat(ports.sendDropped()).isZero();
        }
    }

    @Test
    void onlyAnAuthenticAnswerOfTheRightCodeToARequestInFlightMatches() throws IOException {
        Server server = server();
        List<RequestPorts.Outstanding> answered = new ArrayList<>();
        try (RequestPorts<RequestPorts.Outstanding> ports =
                ports(1, List.of(server), Duration.ofSeconds(5), 0, false)) {
            RequestPorts.Outstanding r = new RequestPorts.Outstanding();
            ports.send(r, System.nanoTime(), RequestPortsTest::accountingRequest);
            DatagramPacket request = server.receive();
            byte[] sent = Arrays.copyOf(request.getData(), request.getLength());
            assertThat(sent).isEqualTo(r.bytes);
            SocketAddress port = request.getSocketAddress();

            server.send(new byte[] {5, 1, 0}, port); // not a RADIUS packet
            server.send(
                    PacketBuilder.reply(RadiusCode.ACCESS_ACCEPT, sent)
                            .secret(SECRET)
                            .build(),
                    port);
            byte[] otherId = sent.clone();
            otherId[1] = (byte) (sent[1] + 1);
            server.send(
                    PacketBuilder.reply(RadiusCode.ACCOUNTING_RESPONSE, otherId)
                            .secret(SECRET)
                            .build(),
                    port);
            server.send(
                    PacketBuilder.reply(RadiusCode.ACCOUNTING_RESPONSE, sent)
                            .secret("wrong")
                            .build(),
                    port);
            receiveUntil(ports, answered, () -> ports.unmatched() == 4);
            assertThat(answered).isEmpty();
            assertThat(ports.inFlight()).isOne();

            byte[] answer = PacketBuilder.reply(RadiusCode.ACCOUNTING_RESPONSE, sent)
                    .secret(SECRET)
                    .build();
            server.send(answer, port);
            receiveUntil(ports, answered, () -> !answered.isEmpty());
            assertThat(answered).containsExactly(r);
            assertThat(ports.inFlight()).isZero();

            server.send(answer, port); // a duplicate: its request is no longer in flight
            receiveUntil(ports, answered, () -> ports.unmatched() == 5);
            assertThat(answered).hasSize(1);
        }
    }

    @Test
    void aLostRequestIsRetriedThroughTheOtherServerAndThenGivenUp() throws IOException {
        Server first = server();
        Server second = server();
        List<RequestPorts.Outstanding> gaveUp = new ArrayList<>();
        try (RequestPorts<RequestPorts.Outstanding> ports =
                ports(1, List.of(first, second), Duration.ofMillis(100), 2, true)) {
            RequestPorts.Outstanding r = new RequestPorts.Outstanding();
            ports.send(r, 0, RequestPortsTest::accountingRequest);
            byte[] sent = first.receiveBytes();

            ports.expire(150 * MS, gaveUp::add);
            assertThat(second.receiveBytes()).as("the identical datagram").isEqualTo(sent);
            assertThat(r.server).isOne();
            ports.expire(300 * MS, gaveUp::add);
            assertThat(first.receiveBytes()).as("and round again").isEqualTo(sent);
            assertThat(r.attempts).isEqualTo(3);
            assertThat(ports.retransmissions()).isEqualTo(2);
            assertThat(gaveUp).isEmpty();

            ports.expire(450 * MS, gaveUp::add);
            assertThat(gaveUp).containsExactly(r);
            assertThat(ports.inFlight()).isZero();
            assertThat(ports.retransmissions()).isEqualTo(2);
        }
    }

    @Test
    void withoutRetryOtherServerARetransmissionGoesToTheSameServer() throws IOException {
        Server first = server();
        Server second = server();
        try (RequestPorts<RequestPorts.Outstanding> ports =
                ports(1, List.of(first, second), Duration.ofMillis(100), 1, false)) {
            RequestPorts.Outstanding r = new RequestPorts.Outstanding();
            ports.send(r, 0, RequestPortsTest::accountingRequest);
            byte[] sent = first.receiveBytes();
            ports.expire(5 * MS, request -> {});
            ports.expire(9 * MS, request -> {}); // within the scan interval: not even looked at
            ports.expire(150 * MS, request -> {});
            assertThat(first.receiveBytes()).isEqualTo(sent);
            assertThat(r.server).isZero();
            assertThat(ports.retransmissions()).isOne();
        }
    }

    @Test
    void aPortThatCannotBeOpenedClosesThoseOpenedBefore() throws IOException {
        Server server = server();
        RuntimeException failure = new IllegalStateException("no more ports");
        int[] opened = {0};
        IntFunction<RequestPorts.Outstanding[]> array = n -> {
            if (opened[0]++ == 1) {
                throw failure;
            }
            return new RequestPorts.Outstanding[n];
        };
        assertThatThrownBy(() -> new RequestPorts<>(
                        2,
                        List.of(server.address()),
                        SECRET,
                        Duration.ofSeconds(1),
                        0,
                        false,
                        code -> true,
                        new Random(1),
                        array))
                .isSameAs(failure);
        assertThat(opened[0]).isEqualTo(2);
    }

    @Test
    void portsForTheRate() {
        assertThat(RequestPorts.portsFor(1000, Duration.ofSeconds(3), 1)).isEqualTo(16);
        assertThat(RequestPorts.portsFor(10, Duration.ofMillis(500), 4)).isEqualTo(4);
    }

    private RequestPorts<RequestPorts.Outstanding> ports(
            int count, List<Server> to, Duration timeout, int retries, boolean retryOtherServer) throws IOException {
        return new RequestPorts<>(
                count,
                to.stream().map(Server::address).toList(),
                SECRET,
                timeout,
                retries,
                retryOtherServer,
                code -> code == RadiusCode.ACCOUNTING_RESPONSE,
                new Random(1),
                RequestPorts.Outstanding[]::new);
    }

    private static byte[] accountingRequest(RequestPorts.Outstanding r, int identifier) {
        return PacketBuilder.accountingRequest(identifier)
                .attribute(44, "s-" + identifier)
                .uint32(40, 1)
                .secret(SECRET)
                .build();
    }

    private static void receiveUntil(
            RequestPorts<RequestPorts.Outstanding> ports, List<RequestPorts.Outstanding> answered, BooleanSupplier done)
            throws IOException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!done.getAsBoolean()) {
            assertThat(System.nanoTime()).as("answers arrived in time").isLessThan(deadline);
            ports.receive((r, answer, latencyMicros) -> {
                assertThat(answer.code()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
                assertThat(latencyMicros).isNotNegative();
                answered.add(r);
            });
        }
    }

    private Server server() throws IOException {
        Server s = new Server(new DatagramSocket(0, InetAddress.getLoopbackAddress()));
        s.socket.setSoTimeout(5_000);
        servers.add(s);
        return s;
    }

    private record Server(DatagramSocket socket) {

        InetSocketAddress address() {
            return new InetSocketAddress(InetAddress.getLoopbackAddress(), socket.getLocalPort());
        }

        DatagramPacket receive() throws IOException {
            DatagramPacket p = new DatagramPacket(new byte[4096], 4096);
            socket.receive(p);
            return p;
        }

        byte[] receiveBytes() throws IOException {
            DatagramPacket p = receive();
            return Arrays.copyOf(p.getData(), p.getLength());
        }

        void send(byte[] datagram, SocketAddress to) throws IOException {
            socket.send(new DatagramPacket(datagram, datagram.length, to));
        }
    }
}
