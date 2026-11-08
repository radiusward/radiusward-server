/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.time.Duration;
import java.util.Arrays;

/**
 * Sends a request over UDP and waits for a matching response, retransmitting the identical datagram
 * on timeout (as a NAS does). Responses with another identifier are ignored.
 */
final class UdpExchange {

    record Result(byte[] response, int attempts, Duration elapsed) {}

    private UdpExchange() {}

    /** @return the response, or {@code null} if all attempts timed out */
    static Result send(InetSocketAddress server, byte[] request, int retries, Duration timeout) throws IOException {
        long start = System.nanoTime();
        try (DatagramChannel channel = DatagramChannel.open();
                Selector selector = Selector.open()) {
            channel.configureBlocking(false);
            channel.connect(server);
            channel.register(selector, SelectionKey.OP_READ);
            ByteBuffer receive = ByteBuffer.allocate(4096);
            int identifier = request[1] & 0xFF;
            for (int attempt = 1; attempt <= retries + 1; attempt++) {
                channel.write(ByteBuffer.wrap(request));
                long deadline = System.nanoTime() + timeout.toNanos();
                long remaining;
                while ((remaining = deadline - System.nanoTime()) > 0) {
                    if (selector.select(Math.max(1, remaining / 1_000_000)) == 0) {
                        continue;
                    }
                    selector.selectedKeys().clear();
                    receive.clear();
                    try {
                        if (channel.read(receive) <= 0) {
                            continue;
                        }
                    } catch (java.net.PortUnreachableException e) {
                        continue; // ICMP port unreachable: nobody listening yet, keep waiting/retrying
                    }
                    receive.flip();
                    if (receive.remaining() >= 20 && (receive.get(1) & 0xFF) == identifier) {
                        byte[] response = Arrays.copyOf(receive.array(), receive.remaining());
                        return new Result(response, attempt, Duration.ofNanos(System.nanoTime() - start));
                    }
                }
            }
            return null;
        }
    }
}
