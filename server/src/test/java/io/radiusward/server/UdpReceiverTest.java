/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class UdpReceiverTest {

    @Test
    void datagramsAreReadInBatchesIntoOneBuffer() throws Exception {
        UdpReceiver receiver = new UdpReceiver("test datagrams");
        assertThat(receiver.localPort()).as("not open yet").isEqualTo(-1);
        receiver.open("127.0.0.1", 0, 1 << 16);
        try (DatagramSocket client = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            int port = receiver.localPort();
            assertThat(port).isPositive();
            for (byte b = 1; b <= 3; b++) {
                client.send(new DatagramPacket(new byte[] {b, b}, 2, InetAddress.getLoopbackAddress(), port));
            }
            List<String> seen = new ArrayList<>();
            UdpReceiver.Datagrams record = (from, length) -> seen.add(
                    from.getPort() + ":" + length + ":" + receiver.received().getByte(0));
            long deadline = System.nanoTime() + 2_000_000_000L;
            int read = 0;
            while (read < 3 && System.nanoTime() < deadline) {
                read += receiver.receive(2, record);
            }
            assertThat(seen)
                    .containsExactly(
                            client.getLocalPort() + ":2:1",
                            client.getLocalPort() + ":2:2",
                            client.getLocalPort() + ":2:3");
            assertThat(receiver.receive(2, record)).as("nothing waiting").isZero();
        } finally {
            receiver.close();
        }
        assertThat(receiver.channel().isOpen()).isFalse();
    }

    @Test
    void aRadsecRequestIsCopiedIntoTheReceiveBuffer() {
        UdpReceiver receiver = new UdpReceiver("test");
        UnsafeBuffer frame = new UnsafeBuffer(new byte[32]);
        frame.putLong(0, 77L); // route
        frame.putInt(8, 1); // connection
        frame.putBytes(12, new byte[] {4, 5, 6});
        assertThat(receiver.copyRadsec(frame, 0, 15)).isEqualTo(3);
        assertThat(receiver.received().getByte(0)).isEqualTo((byte) 4);
        assertThat(receiver.received().getByte(2)).isEqualTo((byte) 6);
        receiver.close(); // never opened: nothing to close
    }
}
