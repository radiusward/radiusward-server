/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.io.IOException;
import java.nio.channels.Selector;
import org.agrona.DirectBuffer;

/**
 * A connection to a home server other than plain UDP (ADR 0045, 0055): RadSec over TLS ({@link TlsClient}), RADIUS over
 * TCP ({@link HomeTcpClient}) or over DTLS ({@link HomeDtlsClient}). Non-blocking, driven by the proxy's selector; whole RADIUS
 * packets go out and come back.
 */
interface HomeConnection {

    boolean open();

    /** Starts connecting; progress comes through {@link #onSelected}. */
    void connect(Selector selector) throws IOException;

    /** Queues a packet; {@code false} if the connection cannot take more (the request is dropped). */
    boolean send(DirectBuffer packet, int offset, int length) throws IOException;

    /** The selector picked this connection; whole packets go to {@code packets}. */
    void onSelected(TlsClient.Packets packets) throws IOException;

    /** Timers (DTLS handshake retransmissions); called regularly with {@link System#nanoTime()}. */
    default void tick(long now) throws IOException {}

    /** Datagrams can be lost: requests are sent again like over UDP. */
    default boolean lossy() {
        return false;
    }

    void close();
}
