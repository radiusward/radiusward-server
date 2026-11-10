/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/** RADIUS over plain TCP to a home server (RFC 6613, ADR 0055): packets back to back on one connection. */
final class HomeTcpClient implements HomeConnection {

    private final InetSocketAddress address;
    private final ByteBuffer in = ByteBuffer.allocate(2 * RadiusPacket.MAX_LENGTH);
    private final UnsafeBuffer inView = new UnsafeBuffer(in);
    private final ByteBuffer out = ByteBuffer.allocate(64 * RadiusPacket.MAX_LENGTH);
    private SocketChannel channel;
    private SelectionKey key;
    private boolean connected;

    HomeTcpClient(InetSocketAddress address) {
        this.address = address;
    }

    @Override
    public boolean open() {
        return channel != null && channel.isOpen();
    }

    @Override
    public void connect(Selector selector) throws IOException {
        close();
        channel = SocketChannel.open();
        channel.configureBlocking(false);
        in.clear();
        out.clear();
        connected = channel.connect(address);
        key = channel.register(selector, connected ? SelectionKey.OP_READ : SelectionKey.OP_CONNECT, this);
    }

    @Override
    public boolean send(DirectBuffer packet, int offset, int length) throws IOException {
        if (!open() || out.remaining() < length) {
            return false;
        }
        packet.getBytes(offset, out, length);
        if (connected) {
            flush();
        }
        return true;
    }

    @Override
    public void onSelected(TlsClient.Packets packets) throws IOException {
        if (key.isConnectable()) {
            if (!channel.finishConnect()) {
                return;
            }
            connected = true;
            flush();
            return;
        }
        if (key.isReadable()) {
            if (channel.read(in) < 0) {
                throw new IOException("closed by the home server");
            }
            in.flip();
            try {
                while (in.remaining() >= 4) {
                    int at = in.position();
                    int length = in.getShort(at + 2) & 0xFFFF;
                    if (length < RadiusPacket.HEADER_LENGTH || length > RadiusPacket.MAX_LENGTH) {
                        throw new IOException("malformed RADIUS packet from the home server");
                    }
                    if (in.remaining() < length) {
                        break;
                    }
                    packets.packet(inView, at, length);
                    in.position(at + length);
                }
            } finally {
                in.compact();
            }
        }
        if (key.isValid() && key.isWritable()) {
            flush();
        }
    }

    private void flush() throws IOException {
        out.flip();
        try {
            channel.write(out);
        } finally {
            out.compact();
        }
        if (key != null && key.isValid()) {
            key.interestOps(out.position() > 0 ? SelectionKey.OP_READ | SelectionKey.OP_WRITE : SelectionKey.OP_READ);
        }
    }

    @Override
    public void close() {
        connected = false;
        if (channel != null) {
            try {
                if (key != null) {
                    key.cancel();
                }
                channel.close();
            } catch (IOException e) {
                // closing anyway
            }
        }
        channel = null;
        key = null;
    }
}
