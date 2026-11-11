/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.AccountingResponses;
import io.radiusward.radius.codec.DecodeStatus;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Minimal RADIUS server on 127.0.0.1 built from the codec: verifies Accounting-Requests and answers them, and, given a
 * password, checks the PAP, CHAP or MS-CHAPv2 credentials of Access-Requests against it and accepts or rejects.
 */
final class LoopbackResponder implements AutoCloseable {

    private final DatagramChannel channel;
    private final Thread thread;
    private final byte[] secret;
    private final int dropFirst;
    private final String password;
    final AtomicInteger received = new AtomicInteger();

    LoopbackResponder(byte[] secret, int dropFirst) throws IOException {
        this(secret, dropFirst, null);
    }

    /** @param password the one password every user has; {@code null}: Access-Requests are ignored */
    LoopbackResponder(byte[] secret, int dropFirst, String password) throws IOException {
        this.secret = secret;
        this.dropFirst = dropFirst;
        this.password = password;
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
                if (packet.wrap(new UnsafeBuffer(data), 0, data.length) == DecodeStatus.OK
                        && packet.code() == RadiusCode.ACCESS_REQUEST) {
                    if (password != null && authenticator.verifyRequestMessageAuthenticator(packet, secret)) {
                        int length = accessReply(packet, data, out, authenticator);
                        channel.send(ByteBuffer.wrap(outBytes, 0, length), from);
                    }
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

    /** Access-Accept when the credentials match the password, otherwise Access-Reject; with Message-Authenticator. */
    private int accessReply(RadiusPacket request, byte[] data, UnsafeBuffer out, RadiusAuthenticator authenticator) {
        boolean ok = switch (new AccessRequests().method(request)) {
            case AccessRequests.METHOD_PAP -> {
                UnsafeBuffer plain = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
                int n = new AccessRequests().decryptUserPassword(request, secret, plain, 0);
                yield n >= 0 && plain.getStringWithoutLengthUtf8(0, n).equals(password);
            }
            case AccessRequests.METHOD_CHAP -> {
                byte[] pw = password.getBytes(StandardCharsets.UTF_8);
                yield new AccessRequests().verifyChap(request, new UnsafeBuffer(pw), 0, pw.length)
                        == AccessRequests.CHAP_MATCH;
            }
            case AccessRequests.METHOD_MS_CHAP2 -> {
                byte[] challenge = vendorAttribute(data, AccessCredentials.MS_CHAP_CHALLENGE);
                byte[] response = vendorAttribute(data, AccessCredentials.MS_CHAP2_RESPONSE);
                yield challenge != null
                        && response != null
                        && response.length == 50
                        && Arrays.equals(
                                Arrays.copyOfRange(response, 26, 50),
                                AccessCredentials.ntResponse(
                                        challenge, Arrays.copyOfRange(response, 2, 18), userName(data), password));
            }
            default -> false;
        };
        RadiusPacketEncoder encoder = new RadiusPacketEncoder();
        encoder.wrap(out, 0).header(ok ? RadiusCode.ACCESS_ACCEPT : RadiusCode.ACCESS_REJECT, request.identifier());
        int messageAuthenticator = encoder.messageAuthenticator();
        int length = encoder.finish();
        authenticator.signResponse(
                out, 0, length, messageAuthenticator, request.buffer(), request.authenticatorOffset(), secret);
        return length;
    }

    /** The value of a Microsoft vendor attribute (RFC 2548), {@code null} if absent. */
    private static byte[] vendorAttribute(byte[] data, int type) {
        for (int at = 20; at + 2 <= data.length && (data[at + 1] & 0xFF) >= 2; at += data[at + 1] & 0xFF) {
            if ((data[at] & 0xFF) == 26
                    && ((data[at + 2] & 0xFF) << 24
                                    | (data[at + 3] & 0xFF) << 16
                                    | (data[at + 4] & 0xFF) << 8
                                    | (data[at + 5] & 0xFF))
                            == AccessCredentials.MICROSOFT
                    && (data[at + 6] & 0xFF) == type) {
                return Arrays.copyOfRange(data, at + 8, at + 6 + (data[at + 7] & 0xFF));
            }
        }
        return null;
    }

    private static String userName(byte[] data) {
        for (int at = 20; at + 2 <= data.length && (data[at + 1] & 0xFF) >= 2; at += data[at + 1] & 0xFF) {
            if (data[at] == 1) {
                return new String(data, at + 2, (data[at + 1] & 0xFF) - 2, StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
