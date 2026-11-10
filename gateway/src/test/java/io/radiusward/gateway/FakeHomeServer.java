/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * A home server for proxy tests (ADR 0037): checks the proxy's Message-Authenticator, decrypts User-Password with its
 * own secret and answers — Accept with an MS-MPPE-Recv-Key, Reject, Challenge with a State — echoing every Proxy-State,
 * or stays silent, or answers without Message-Authenticator. Status-Server gets an Access-Accept unless silent.
 */
final class FakeHomeServer implements AutoCloseable {

    enum Mode {
        ACCEPT,
        REJECT,
        CHALLENGE,
        SILENT,
        NO_MESSAGE_AUTHENTICATOR
    }

    record Seen(byte[] packet, String user, String password) {}

    static final byte[] MPPE_KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    final byte[] secret;
    final DatagramChannel channel;
    final List<Seen> requests = new CopyOnWriteArrayList<>();
    final AtomicInteger statusServers = new AtomicInteger();
    volatile Mode mode = Mode.ACCEPT;
    private final Thread thread;

    FakeHomeServer(String secret) throws Exception {
        this.secret = secret.getBytes(StandardCharsets.US_ASCII);
        channel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        thread = new Thread(this::serve, "fake-home");
        thread.setDaemon(true);
        thread.start();
    }

    int port() throws Exception {
        return ((InetSocketAddress) channel.getLocalAddress()).getPort();
    }

    private void serve() {
        ByteBuffer in = ByteBuffer.allocate(4096);
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        while (true) {
            try {
                in.clear();
                InetSocketAddress from = (InetSocketAddress) channel.receive(in);
                byte[] bytes = Arrays.copyOf(in.array(), in.position());
                RadiusPacket p = new RadiusPacket();
                p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
                if (!authenticator.verifyRequestMessageAuthenticator(p, secret)) {
                    continue; // wrong secret or none: like a real server, silence
                }
                if (p.code() == RadiusCode.STATUS_SERVER) {
                    if (mode != Mode.SILENT) {
                        statusServers.incrementAndGet();
                        channel.send(ByteBuffer.wrap(answer(p, bytes, RadiusCode.ACCESS_ACCEPT, true)), from);
                    }
                    continue;
                }
                String password = null;
                if (p.findAttribute(2) >= 0) {
                    UnsafeBuffer plain = new UnsafeBuffer(new byte[128]);
                    int n = new AccessRequests().decryptUserPassword(p, secret, plain, 0);
                    password = new String(plain.byteArray(), 0, n, StandardCharsets.UTF_8);
                }
                int at = p.findAttribute(1);
                String user =
                        at < 0 ? null : new String(bytes, at + 2, (bytes[at + 1] & 0xFF) - 2, StandardCharsets.UTF_8);
                requests.add(new Seen(bytes, user, password));
                switch (mode) {
                    case SILENT -> {}
                    case REJECT ->
                        channel.send(ByteBuffer.wrap(answer(p, bytes, RadiusCode.ACCESS_REJECT, true)), from);
                    case CHALLENGE ->
                        channel.send(ByteBuffer.wrap(answer(p, bytes, RadiusCode.ACCESS_CHALLENGE, true)), from);
                    case NO_MESSAGE_AUTHENTICATOR ->
                        channel.send(ByteBuffer.wrap(answer(p, bytes, RadiusCode.ACCESS_ACCEPT, false)), from);
                    default -> channel.send(ByteBuffer.wrap(answer(p, bytes, RadiusCode.ACCESS_ACCEPT, true)), from);
                }
            } catch (Exception e) {
                return; // closed
            }
        }
    }

    private byte[] answer(RadiusPacket request, byte[] bytes, int code, boolean withMa) {
        UnsafeBuffer out = new UnsafeBuffer(new byte[4096]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(out, 0).header(code, request.identifier());
        int ma = withMa ? enc.messageAuthenticator() : -1;
        if (code == RadiusCode.ACCESS_ACCEPT && request.code() == RadiusCode.ACCESS_REQUEST) {
            enc.attribute(18, "home says hello");
            byte[] salt = {(byte) 0x80, 0x01};
            byte[] key = MsChap.encryptKey(MPPE_KEY, secret, Arrays.copyOfRange(bytes, 4, 20), salt);
            enc.vendorAttribute(311, 17, key); // MS-MPPE-Recv-Key
        }
        if (code == RadiusCode.ACCESS_CHALLENGE) {
            enc.attribute(24, "home-state");
        }
        for (int at = request.attributesOffset(); at < request.attributesEnd(); ) {
            int l = bytes[at + 1] & 0xFF;
            if ((bytes[at] & 0xFF) == 33) {
                enc.rawAttribute(new UnsafeBuffer(bytes), at); // every Proxy-State, in order
            }
            at += l;
        }
        int length = enc.finish();
        new RadiusAuthenticator().signResponse(out, 0, length, ma, new UnsafeBuffer(bytes), 4, secret);
        return Arrays.copyOf(out.byteArray(), length);
    }

    @Override
    public void close() throws java.io.IOException {
        channel.close(); // the serving thread ends on the closed channel
    }
}
