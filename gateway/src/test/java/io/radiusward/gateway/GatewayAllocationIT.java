/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.AccountingCommandDecoder;
import io.radiusward.protocol.AccountingCommittedEncoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.Outcome;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import org.agrona.concurrent.MessageHandler;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.OneToOneRingBuffer;
import org.junit.jupiter.api.Test;

/**
 * The gateway's per-packet path — receive, validate, authenticate, cache, extract, keys, submit, commit,
 * build and send the response — must not allocate. One sender, so the JDK reuses its cached sender address
 * (with many NAS the JDK allocates ~80 bytes per sender change; documented in ADR 0011).
 */
class GatewayAllocationIT {

    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
    private static final int PACKETS = 100_000;

    @Test
    void receiveSubmitCommitRespondDoesNotAllocate() throws Exception {
        measure(UdpAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OPTIONAL), false);
    }

    /** Devices behind NAT (ADR 0019): identity lookup, MAC normalisation and the longer keys stay allocation-free. */
    @Test
    void deviceIdentityDoesNotAllocate() throws Exception {
        measure(UdpAgentTest.natRegistry(), true);
    }

    private static void measure(NasRegistry registry, boolean devices) throws Exception {
        long[] clock = {1_000_000_000L};
        GatewayStats stats = new GatewayStats();
        OneToOneRingBuffer toCluster = UdpAgentTest.ring();
        OneToOneRingBuffer fromCluster = UdpAgentTest.ring();
        UdpAgent agent = new UdpAgent(
                UdpAgentTest.config(Duration.ZERO, 1024),
                registry,
                UdpAgentTest.FORMATS,
                toCluster,
                fromCluster,
                stats,
                () -> clock[0]);
        agent.onStart();
        try (DatagramChannel client = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
            client.configureBlocking(false);
            client.connect(new InetSocketAddress("127.0.0.1", agent.localPort()));

            ByteBuffer[] packets = buildPackets(2 * PACKETS, devices);
            ByteBuffer response = ByteBuffer.allocateDirect(4096);
            FakeCluster cluster = new FakeCluster(fromCluster);

            run(agent, client, packets, 0, PACKETS, toCluster, cluster, response, clock); // warm-up
            long before = THREADS.getCurrentThreadAllocatedBytes();
            run(agent, client, packets, PACKETS, PACKETS, toCluster, cluster, response, clock);
            long allocated = THREADS.getCurrentThreadAllocatedBytes() - before;

            assertThat(stats.get(GatewayStats.Counter.RESPONSES_SENT)).isEqualTo(2L * PACKETS);
            assertThat(allocated)
                    .as("bytes allocated for %d packets (%.3f per packet)", PACKETS, (double) allocated / PACKETS)
                    .isLessThan(64 * 1024);
        } finally {
            agent.onClose();
        }
    }

    private static void run(
            UdpAgent agent,
            DatagramChannel client,
            ByteBuffer[] packets,
            int from,
            int count,
            OneToOneRingBuffer toCluster,
            FakeCluster cluster,
            ByteBuffer response,
            long[] clock)
            throws Exception {
        for (int i = from; i < from + count; i++) {
            packets[i].clear();
            client.write(packets[i]);
            clock[0] += 1_000_000; // 1 ms per packet: cache entries expire, so its size stays steady
            int responses = 0;
            for (int spin = 0; responses == 0 && spin < 1_000_000; spin++) {
                agent.doWork();
                toCluster.read(cluster);
                agent.doWork();
                response.clear();
                responses = client.read(response);
            }
            if (responses <= 0) {
                throw new AssertionError("no response for packet " + i);
            }
        }
    }

    /** Answers every command with AccountingCommitted, like the cluster leader. */
    static final class FakeCluster implements MessageHandler {
        private final OneToOneRingBuffer fromCluster;
        private final MessageHeaderDecoder header = new MessageHeaderDecoder();
        private final AccountingCommandDecoder command = new AccountingCommandDecoder();
        private final AccountingCommittedEncoder committed = new AccountingCommittedEncoder();
        private final MessageHeaderEncoder headerEncoder = new MessageHeaderEncoder();
        private final UnsafeBuffer out = new UnsafeBuffer(new byte[64]);

        FakeCluster(OneToOneRingBuffer fromCluster) {
            this.fromCluster = fromCluster;
        }

        @Override
        public void onMessage(int msgTypeId, org.agrona.MutableDirectBuffer buffer, int index, int length) {
            command.wrapAndApplyHeader(buffer, index, header.wrap(buffer, index));
            committed
                    .wrapAndApplyHeader(out, 0, headerEncoder)
                    .correlationId(command.correlationId())
                    .outcome(Outcome.APPLIED)
                    .eventId(index);
            fromCluster.write(
                    UdpAgent.COMMITTED_MSG, out, 0, MessageHeaderEncoder.ENCODED_LENGTH + committed.encodedLength());
        }
    }

    /** Distinct signed interim updates (different session time → different event, different authenticator). */
    private static ByteBuffer[] buildPackets(int n, boolean devices) {
        ByteBuffer[] packets = new ByteBuffer[n];
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder();
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        for (int i = 0; i < n; i++) {
            int length = encoder.wrap(buffer, 0)
                    .header(RadiusCode.ACCOUNTING_REQUEST, i & 0xFF)
                    .uint32(40, 3)
                    .attribute(44, "session-" + (i % 1000))
                    .attribute(1, "user@isp.example")
                    // no NAS-Identifier: the second identity, the MAC in Called-Station-Id, is normalised
                    .attribute(devices ? 30 : 31, String.format("AA-BB-CC-DD-EE-%02X:Guest", i % 50))
                    .ipv4(4, 0x7F000001L)
                    .uint32(46, i)
                    .uint32(42, i * 10L)
                    .uint32(43, i * 20L)
                    .uint32(55, 1_780_000_000L + i)
                    .vendorAttribute(9, 1, "connect-progress=LAN Ses Up")
                    .finish();
            authenticator.signAccountingRequest(buffer, 0, length, -1, UdpAgentTest.SECRET);
            ByteBuffer packet = ByteBuffer.allocateDirect(length);
            buffer.getBytes(0, packet, length);
            packets[i] = packet;
        }
        return packets;
    }

    /** Access-Requests (Phase 5.2): receive, slot, worker decision, signed reply, send — no allocation per request. */
    @Test
    void accessRequestPathDoesNotAllocate() throws Exception {
        long[] clock = {1_000_000_000L};
        AuthStats stats = new AuthStats();
        AccessSlots slots = new AccessSlots(64);
        UnsafeBuffer password = new UnsafeBuffer(new byte[128]);
        AccessHandler handler = context -> {
            int n = context.credentials()
                    .decryptUserPassword(context.request(), context.nas().secret(), password, 0);
            context.reply().uint32(27, 3600);
            return n == 10 ? AccessHandler.ACCEPT : AccessHandler.REJECT;
        };
        AuthAgent agent = new AuthAgent(
                UdpAgentTest.config(Duration.ZERO, 1024),
                new AuthConfig(true, 0, 1, 64, 4096, Duration.ofMillis(1)),
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.REQUIRED),
                slots,
                stats,
                () -> clock[0]);
        AccessWorker worker = new AccessWorker(0, slots, handler, stats);
        agent.onStart();
        try (DatagramChannel client = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0))) {
            client.configureBlocking(false);
            client.connect(new InetSocketAddress("127.0.0.1", agent.localPort()));
            ByteBuffer[] requests = new ByteBuffer[2 * PACKETS];
            for (int i = 0; i < requests.length; i++) {
                byte[] r = AuthAgentTest.accessRequest(i & 0xFF, "arctangent", true, false);
                requests[i] = ByteBuffer.allocateDirect(r.length).put(r).flip();
            }
            ByteBuffer response = ByteBuffer.allocateDirect(4096);
            runAccess(agent, worker, client, requests, 0, PACKETS, response, clock); // warm-up
            long before = THREADS.getCurrentThreadAllocatedBytes();
            runAccess(agent, worker, client, requests, PACKETS, PACKETS, response, clock);
            long allocated = THREADS.getCurrentThreadAllocatedBytes() - before;
            assertThat(stats.get(AuthStats.Counter.ACCEPTED)).isEqualTo(2L * PACKETS);
            assertThat(allocated)
                    .as(
                            "bytes allocated for %d Access-Requests (%.3f per request)",
                            PACKETS, (double) allocated / PACKETS)
                    .isLessThan(64 * 1024);
        } finally {
            agent.onClose();
        }
    }

    private static void runAccess(
            AuthAgent agent,
            AccessWorker worker,
            DatagramChannel client,
            ByteBuffer[] requests,
            int from,
            int count,
            ByteBuffer response,
            long[] clock)
            throws Exception {
        for (int i = from; i < from + count; i++) {
            requests[i].clear();
            client.write(requests[i]);
            clock[0] += 2_000_000; // 2 ms per request: cached replies expire, the cache stays small
            int responses = 0;
            for (int spin = 0; responses == 0 && spin < 1_000_000; spin++) {
                agent.doWork();
                worker.doWork();
                agent.doWork();
                response.clear();
                responses = client.read(response);
            }
            if (responses <= 0) {
                throw new AssertionError("no reply for request " + i);
            }
        }
    }
}
