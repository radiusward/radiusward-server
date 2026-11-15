/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayDeque;
import java.util.List;
import java.util.function.IntFunction;

/**
 * One UDP socket of a load generator and its 256 RADIUS identifiers: the request waiting under each, and the free
 * ones. Registered with a selector, so an answer finds its socket through {@link #of(SelectionKey)}.
 */
final class RequestPort<R> {

    static final int IDS = 256;

    final DatagramChannel channel;
    final R[] inFlight;
    final ArrayDeque<Integer> freeIds = new ArrayDeque<>();

    RequestPort(Selector selector, InetAddress local, IntFunction<R[]> array) throws IOException {
        inFlight = array.apply(IDS);
        channel = DatagramChannel.open();
        try {
            channel.bind(new InetSocketAddress(local, 0));
            channel.configureBlocking(false);
            channel.register(selector, SelectionKey.OP_READ, this);
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
        for (int i = 0; i < IDS; i++) {
            freeIds.add(i);
        }
    }

    /** The port a selection key was registered for. */
    @SuppressWarnings("unchecked")
    static <R> RequestPort<R> of(SelectionKey key) {
        return (RequestPort<R>) key.attachment();
    }

    /**
     * The address to bind the ports to: loopback when every server is local, otherwise the wildcard ({@code null}). A
     * specific bind matters on a shared host: other programs binding {@code 127.0.0.1:0} with address reuse (Aeron
     * does) can otherwise be given a port this generator holds on the wildcard address and take its responses (seen
     * in the in-JVM tests: whole ports of 256 requests lost).
     */
    static InetAddress localAddress(List<InetSocketAddress> servers) {
        boolean loopback = servers.stream()
                .allMatch(s -> s.getAddress() != null && s.getAddress().isLoopbackAddress());
        return loopback ? InetAddress.getLoopbackAddress() : null;
    }

    /** The {@code p}th percentile of sorted values (nearest rank), 0 when there are none. */
    static long percentile(long[] sorted, int p) {
        if (sorted.length == 0) {
            return 0;
        }
        return sorted[Math.min(sorted.length - 1, (int) Math.ceil(p / 100.0 * sorted.length) - 1)];
    }
}
