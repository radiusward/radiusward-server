/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.AccountingResponses;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.concurrent.UnsafeBuffer;

/** Minimal accounting server on 127.0.0.1 built from the codec: verifies requests and answers them. */
final class LoopbackResponder implements AutoCloseable {

    private final DatagramChannel channel;
    private final Thread thread;
    private final byte[] secret;
    private final int dropFirst;
    final AtomicInteger received = new AtomicInteger();

    LoopbackResponder(byte[] secret, int dropFirst) throws IOException {
        this.secret = secret;
        this.dropFirst = dropFirst;
        this.channel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        this.thread = new Thread(this::serve, "loopback-responder");
        thread.setDaemon(true);
        thread.start();
    }

    String address() throws IOException {
        InetSocketAddress local = (InetSocketAddress) channel.getLocalAddress();
        return "127.0.0.1:" + local.getPort();
    }

    private void serve() {
        ByteBuffer in = ByteBuffer.allocate(4096);
        byte[] outBytes = new byte[4096];
        UnsafeBuffer out = new UnsafeBuffer(outBytes);
        RadiusPacket packet = new RadiusPacket();
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        AccountingResponses responses = new AccountingResponses(authenticator);
        try {
            while (true) {
                in.clear();
                SocketAddress from = channel.receive(in);
                int n = received.incrementAndGet();
                in.flip();
                byte[] data = new byte[in.remaining()];
                in.get(data);
                if (n <= dropFirst) {
                    continue;
                }
                if (packet.wrap(new UnsafeBuffer(data), 0, data.length) != DecodeStatus.OK
                        || !authenticator.verifyAccountingRequest(packet, secret)) {
                    continue; // silently discard, as RFC 2866 requires
                }
                int length = responses.encode(packet, out, 0, secret, packet.hasMessageAuthenticator());
                channel.send(ByteBuffer.wrap(outBytes, 0, length), from);
            }
        } catch (IOException e) {
            // closed
        }
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
