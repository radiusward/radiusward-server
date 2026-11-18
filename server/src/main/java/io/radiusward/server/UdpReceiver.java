/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import org.agrona.BufferUtil;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A gateway agent's RADIUS socket: bound non-blocking, read in batches into one receive buffer, which also takes the
 * requests that arrive from a RadSec connection. Owned by one agent and used on its thread only; allocation-free
 * after {@link #open}.
 */
final class UdpReceiver {

    private static final Logger LOG = LogManager.getLogger(UdpReceiver.class);

    /** A datagram of {@code length} bytes from {@code from}, in {@link #received()}. */
    interface Datagrams {
        void onDatagram(InetSocketAddress from, int length);
    }

    private final String purpose;
    private final ByteBuffer receiveBuffer = BufferUtil.allocateDirectAligned(RadiusPacket.MAX_LENGTH + 64, 64);
    private final UnsafeBuffer received = new UnsafeBuffer(receiveBuffer);
    private DatagramChannel channel;

    /** @param purpose what the socket receives, for the log ({@code RADIUS accounting}) */
    UdpReceiver(String purpose) {
        this.purpose = purpose;
    }

    void open(String host, int port, int socketReceiveBuffer) throws IOException {
        channel = DatagramChannel.open();
        try {
            channel.setOption(StandardSocketOptions.SO_RCVBUF, socketReceiveBuffer);
            channel.bind(new InetSocketAddress(host, port));
            channel.configureBlocking(false);
        } catch (IOException | RuntimeException e) {
            channel.close();
            throw e;
        }
        LOG.info("listening for {} on {}", purpose, channel.getLocalAddress());
    }

    /** The port bound (useful when configured as 0); -1 before {@link #open}. */
    int localPort() {
        try {
            return channel == null ? -1 : ((InetSocketAddress) channel.getLocalAddress()).getPort();
        } catch (IOException e) {
            return -1;
        }
    }

    /** The socket, for replies from the same address and port. */
    DatagramChannel channel() {
        return channel;
    }

    /** Where the datagram or RadSec request being handled is. */
    UnsafeBuffer received() {
        return received;
    }

    /** Hands up to {@code batch} waiting datagrams to {@code datagrams}; how many there were. */
    int receive(int batch, Datagrams datagrams) throws IOException {
        int work = 0;
        for (int i = 0; i < batch; i++) {
            receiveBuffer.clear();
            SocketAddress from = channel.receive(receiveBuffer);
            if (from == null) {
                break;
            }
            datagrams.onDatagram((InetSocketAddress) from, receiveBuffer.position());
            work++;
        }
        return work;
    }

    /**
     * A request a RadSec connection passed on ({@link RadsecLink}: route, connection, then the packet at 12): copied
     * into the receive buffer; its length.
     */
    int copyRadsec(DirectBuffer frame, int index, int length) {
        int packetLength = length - 12;
        received.putBytes(0, frame, index + 12, packetLength);
        return packetLength;
    }

    void close() {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException e) {
                LOG.warn("closing the {} socket: {}", purpose, e.toString());
            }
        }
    }
}
