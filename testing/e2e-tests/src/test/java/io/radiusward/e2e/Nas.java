/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.gateway.EventKeys;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.testing.LocalCluster;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;

/** A simulated NAS with a fixed source port, retransmitting like a real one. */
final class Nas implements AutoCloseable {

    static final byte[] SECRET = ProcessCluster.SECRET.getBytes(StandardCharsets.US_ASCII);

    private final DatagramChannel channel;

    Nas() throws IOException {
        channel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        channel.configureBlocking(false);
    }

    /** Sends and waits for a verified Accounting-Response; {@code null} if none arrives within the attempts. */
    byte[] exchange(int port, byte[] request, int attempts, Duration timeout) throws IOException, InterruptedException {
        InetSocketAddress target = new InetSocketAddress("127.0.0.1", port);
        ByteBuffer in = ByteBuffer.allocate(4096);
        for (int attempt = 0; attempt < attempts; attempt++) {
            channel.send(ByteBuffer.wrap(request), target);
            long deadline = System.nanoTime() + timeout.toNanos();
            while (System.nanoTime() < deadline) {
                in.clear();
                if (channel.receive(in) != null) {
                    byte[] response = Arrays.copyOf(in.array(), in.position());
                    RadiusPacket view = new RadiusPacket();
                    view.wrap(new UnsafeBuffer(response), 0, response.length);
                    if (view.identifier() == (request[1] & 0xFF)
                            && new RadiusAuthenticator().verifyResponse(view, new UnsafeBuffer(request), 4, SECRET)) {
                        assertThat(view.code()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
                        return response;
                    }
                }
                Thread.sleep(2);
            }
        }
        return null;
    }

    /** Like {@link #exchange} with NAS-like defaults (3 s, many attempts), failing if there is no answer. */
    byte[] ack(int port, byte[] request) throws IOException, InterruptedException {
        byte[] response = exchange(port, request, 10, Duration.ofSeconds(3));
        assertThat(response).as("Accounting-Response").isNotNull();
        return response;
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime, int delay) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id).uint32(40, status);
        if (sessionId != null) {
            enc.attribute(44, sessionId);
        }
        enc.uint32(55, 1_780_000_000L + sessionTime);
        if (status == 2 || status == 3) {
            enc.uint32(46, sessionTime).uint32(42, sessionTime * 1000);
        }
        if (delay > 0) {
            enc.uint32(41, delay);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    static byte[] request(int id, int status, String sessionId, long sessionTime) {
        return request(id, status, sessionId, sessionTime, 0);
    }

    static long[] sessionKey(String sessionId) {
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(sessionId.getBytes(StandardCharsets.US_ASCII));
        keys.compute(LocalCluster.NAS_ID, 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        return new long[] {keys.sessionHi(), keys.sessionLo()};
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
