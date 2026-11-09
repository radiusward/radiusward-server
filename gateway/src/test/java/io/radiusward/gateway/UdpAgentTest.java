/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.Profile;
import io.radiusward.protocol.AccountingCommandDecoder;
import io.radiusward.protocol.AccountingCommittedEncoder;
import io.radiusward.protocol.AccountingRejectedEncoder;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.Outcome;
import io.radiusward.protocol.RejectReason;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.codec.VendorFormats;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.agrona.BufferUtil;
import org.agrona.concurrent.UnsafeBuffer;
import org.agrona.concurrent.ringbuffer.OneToOneRingBuffer;
import org.agrona.concurrent.ringbuffer.RingBufferDescriptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The UDP agent over real loopback UDP, with the cluster played by the test through the ring buffers. */
class UdpAgentTest {

    static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);
    static final VendorFormats FORMATS = VendorFormats.from(DictionaryLoader.loadBundled());

    record Command(
            long correlationId,
            int nasId,
            long status,
            long sessionHi,
            long sessionLo,
            long exactHi,
            long exactLo,
            String sessionId,
            long sessionTime,
            long inputOctets,
            int nasClientId,
            String nasDevice,
            boolean deviceUnknown) {}

    private final long[] clock = {1_000_000_000L};
    private final GatewayStats stats = new GatewayStats();
    private OneToOneRingBuffer toCluster;
    private OneToOneRingBuffer fromCluster;
    private UdpAgent agent;
    private DatagramChannel client;

    static GatewayConfig config(Duration delay, int pendingCapacity) {
        return new GatewayConfig(
                1,
                "127.0.0.1",
                0,
                1 << 20,
                List.of("localhost"),
                9000,
                "localhost",
                Profile.SMALL,
                pendingCapacity,
                Duration.ofSeconds(10),
                Duration.ofSeconds(1),
                Duration.ofSeconds(30),
                false,
                Profile.SMALL.idleStrategyName(),
                "/tmp/unused",
                null,
                delay);
    }

    static NasRegistry registry(NasClient.MessageAuthenticatorPolicy policy) {
        return NasRegistry.of(List.of(new NasClient("local", 1001, 0x7F000001, 32, SECRET, "default", policy)));
    }

    void start(GatewayConfig config, NasRegistry registry) throws IOException {
        toCluster = ring();
        fromCluster = ring();
        agent = new UdpAgent(config, registry, FORMATS, toCluster, fromCluster, stats, () -> clock[0]);
        agent.onStart();
        client = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
        client.configureBlocking(false);
        client.connect(new InetSocketAddress("127.0.0.1", agent.localPort()));
    }

    void start() throws IOException {
        start(config(Duration.ZERO, 1024), registry(NasClient.MessageAuthenticatorPolicy.OPTIONAL));
    }

    static OneToOneRingBuffer ring() {
        return new OneToOneRingBuffer(new UnsafeBuffer(
                BufferUtil.allocateDirectAligned((1 << 16) + RingBufferDescriptor.TRAILER_LENGTH, 64)));
    }

    @AfterEach
    void stop() throws IOException {
        if (agent != null) {
            agent.onClose();
        }
        if (client != null) {
            client.close();
        }
    }

    // ---- helpers ---------------------------------------------------------------------------------

    void send(byte[] packet) throws Exception {
        client.write(ByteBuffer.wrap(packet));
        work();
    }

    void work() throws Exception {
        for (int i = 0; i < 20; i++) {
            agent.doWork();
            Thread.sleep(1);
        }
    }

    List<Command> commands() {
        List<Command> commands = new ArrayList<>();
        MessageHeaderDecoder header = new MessageHeaderDecoder();
        AccountingCommandDecoder d = new AccountingCommandDecoder();
        toCluster.read((type, buffer, index, length) -> {
            d.wrapAndApplyHeader(buffer, index, header.wrap(buffer, index));
            commands.add(new Command(
                    d.correlationId(),
                    d.nasId(),
                    d.statusType(),
                    d.sessionKeyHi(),
                    d.sessionKeyLo(),
                    d.exactKeyHi(),
                    d.exactKeyLo(),
                    d.sessionId(),
                    d.sessionTime(),
                    d.inputOctets(),
                    d.nasClientId(),
                    nasDevice(d),
                    d.flags().deviceUnknown()));
        });
        return commands;
    }

    private static String nasDevice(AccountingCommandDecoder d) {
        d.skipRawAttributes();
        return d.nasDevice();
    }

    void commit(long correlationId, Outcome outcome) throws Exception {
        UnsafeBuffer b = new UnsafeBuffer(new byte[64]);
        AccountingCommittedEncoder e = new AccountingCommittedEncoder();
        e.wrapAndApplyHeader(b, 0, new MessageHeaderEncoder())
                .correlationId(correlationId)
                .outcome(outcome)
                .eventId(7);
        fromCluster.write(UdpAgent.COMMITTED_MSG, b, 0, MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength());
        work();
    }

    void reject(long correlationId) throws Exception {
        UnsafeBuffer b = new UnsafeBuffer(new byte[64]);
        AccountingRejectedEncoder e = new AccountingRejectedEncoder();
        e.wrapAndApplyHeader(b, 0, new MessageHeaderEncoder())
                .correlationId(correlationId)
                .reason(RejectReason.CAPACITY);
        fromCluster.write(UdpAgent.REJECTED_MSG, b, 0, MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength());
        work();
    }

    byte[] receive() throws IOException {
        ByteBuffer in = ByteBuffer.allocate(4096);
        int n = client.read(in);
        return n <= 0 ? null : Arrays.copyOf(in.array(), n);
    }

    static RadiusPacket wrap(byte[] bytes) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return p;
    }

    static boolean verifiesAgainst(byte[] response, byte[] request) {
        return new RadiusAuthenticator().verifyResponse(wrap(response), new UnsafeBuffer(request), 4, SECRET);
    }

    static byte[] fixture(String vendor, String event) throws IOException {
        return fixture(Path.of("../radius-codec/src/test/resources/fixtures", vendor, event + ".fixture"));
    }

    static byte[] fixture(Path file) throws IOException {
        for (String line : Files.readAllLines(file)) {
            if (line.startsWith("packet:")) {
                return HexFormat.of().parseHex(line.substring(7).trim());
            }
        }
        throw new IllegalStateException("no packet in " + file);
    }

    /** Same event retransmitted by a NAS: new Identifier, Acct-Delay-Time added, re-signed. */
    static byte[] retransmitted(byte[] original, int identifier, int delaySeconds) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        buffer.putBytes(0, original);
        buffer.putByte(1, (byte) identifier);
        int length = original.length;
        buffer.putByte(length, (byte) 41);
        buffer.putByte(length + 1, (byte) 6);
        buffer.putInt(length + 2, delaySeconds, java.nio.ByteOrder.BIG_ENDIAN);
        length += 6;
        buffer.putShort(2, (short) length, java.nio.ByteOrder.BIG_ENDIAN);
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    static byte[] request(int identifier, boolean withMa, String sessionId, int status) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, identifier)
                .uint32(40, status)
                .attribute(44, sessionId)
                .attribute(33, "proxy-a")
                .attribute(33, "proxy-b");
        int ma = withMa ? enc.messageAuthenticator() : -1;
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, ma, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    // ---- tests -----------------------------------------------------------------------------------

    @Test
    void submittedThenAnsweredOnlyAfterCommit() throws Exception {
        start();
        byte[] start = fixture("cisco", "start");
        send(start);
        List<Command> commands = commands();
        assertThat(commands).hasSize(1);
        Command c = commands.get(0);
        assertThat(c.nasId()).isEqualTo(1001);
        assertThat(c.status()).isEqualTo(1);
        assertThat(c.sessionId()).isEqualTo("00000A1B");
        assertThat(receive()).as("no ACK before commit").isNull();

        commit(c.correlationId(), Outcome.APPLIED);
        byte[] response = receive();
        assertThat(response).isNotNull();
        assertThat(wrap(response).code()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
        assertThat(wrap(response).identifier()).isEqualTo(wrap(start).identifier());
        assertThat(verifiesAgainst(response, start)).isTrue();
        assertThat(stats.get(GatewayStats.Counter.COMMITTED)).isEqualTo(1);
        assertThat(stats.get(GatewayStats.Counter.RESPONSES_SENT)).isEqualTo(1);
    }

    @Test
    void retransmitsWhilePendingAreDroppedAndAfterCommitAnsweredFromCache() throws Exception {
        start();
        byte[] packet = fixture("huawei", "interim");
        send(packet);
        send(packet);
        List<Command> commands = commands();
        assertThat(commands).as("one submission only").hasSize(1);
        assertThat(stats.get(GatewayStats.Counter.RETRANSMIT_IN_FLIGHT)).isEqualTo(1);

        commit(commands.get(0).correlationId(), Outcome.APPLIED);
        assertThat(receive()).isNotNull();
        send(packet);
        byte[] cached = receive();
        assertThat(cached).as("answered from the cache").isNotNull();
        assertThat(verifiesAgainst(cached, packet)).isTrue();
        assertThat(commands()).as("no cluster round trip").isEmpty();
        assertThat(stats.get(GatewayStats.Counter.CACHE_HITS)).isEqualTo(1);
    }

    @Test
    void eventKeysIgnoreIdentifierAndDelayForAllFixtures() throws Exception {
        start(config(Duration.ZERO, 4096), registry(NasClient.MessageAuthenticatorPolicy.OPTIONAL));
        List<Path> fixtures;
        try (Stream<Path> walk = Files.walk(Path.of("../radius-codec/src/test/resources/fixtures"))) {
            fixtures =
                    walk.filter(p -> p.toString().endsWith(".fixture")).sorted().toList();
        }
        assertThat(fixtures).hasSizeGreaterThanOrEqualTo(21);
        for (Path file : fixtures) {
            byte[] original = fixture(file);
            send(original);
            send(retransmitted(original, (original[1] + 1) & 0xFF, 5));
            List<Command> commands = commands();
            assertThat(commands).as(file.toString()).hasSize(2);
            Command a = commands.get(0);
            Command b = commands.get(1);
            assertThat(b.sessionHi()).as(file + " session key").isEqualTo(a.sessionHi());
            assertThat(b.sessionLo()).isEqualTo(a.sessionLo());
            assertThat(b.exactHi()).as(file + " exact key").isEqualTo(a.exactHi());
            assertThat(b.exactLo()).isEqualTo(a.exactLo());
            commit(a.correlationId(), Outcome.APPLIED);
            commit(b.correlationId(), Outcome.DUPLICATE);
            assertThat(receive()).isNotNull();
            assertThat(receive()).isNotNull();
        }
    }

    @Test
    void sixtyFourBitCountersAreCombined() throws Exception {
        start();
        send(fixture("cisco", "stop"));
        Command c = commands().get(0);
        assertThat(c.sessionTime()).isEqualTo(7260);
        assertThat(c.inputOctets()).isEqualTo(734_003_200L);
    }

    @Test
    void rejectedOrInvalidPacketsAreSilent() throws Exception {
        start(
                config(Duration.ZERO, 16),
                NasRegistry.of(List.of(new NasClient(
                        "other", 1, 0x0A000001, 32, SECRET, "default", NasClient.MessageAuthenticatorPolicy.OFF))));
        send(fixture("cisco", "start"));
        assertThat(stats.get(GatewayStats.Counter.UNKNOWN_NAS)).isEqualTo(1);
        agent.onClose();
        client.close();

        start();
        byte[] tampered = fixture("cisco", "start");
        tampered[tampered.length - 1] ^= 1;
        send(tampered);
        assertThat(stats.get(GatewayStats.Counter.AUTHENTICATOR_FAILED)).isEqualTo(1);
        send(new byte[] {4, 1, 0, 30});
        assertThat(stats.get(GatewayStats.Counter.MALFORMED)).isEqualTo(1);
        byte[] accessRequest = fixture("cisco", "start");
        accessRequest[0] = RadiusCode.ACCESS_REQUEST;
        send(accessRequest);
        assertThat(stats.get(GatewayStats.Counter.NOT_ACCOUNTING)).isEqualTo(1);
        assertThat(commands()).isEmpty();
        assertThat(receive()).isNull();

        byte[] packet = request(9, false, "s-rej", 1);
        send(packet);
        reject(commands().get(0).correlationId());
        assertThat(receive()).as("rejected: stay silent").isNull();
        send(packet);
        assertThat(commands()).as("cache cleared, retransmit resubmitted").hasSize(1);
    }

    @Test
    void messageAuthenticatorPolicyAndProxyState() throws Exception {
        start(config(Duration.ZERO, 16), registry(NasClient.MessageAuthenticatorPolicy.REQUIRED));
        send(request(1, false, "s1", 1));
        assertThat(stats.get(GatewayStats.Counter.MESSAGE_AUTHENTICATOR_FAILED)).isEqualTo(1);
        assertThat(commands()).isEmpty();

        byte[] withMa = request(2, true, "s2", 1);
        send(withMa);
        Command c = commands().get(0);
        commit(c.correlationId(), Outcome.APPLIED);
        byte[] response = receive();
        RadiusPacket view = wrap(response);
        assertThat(view.hasMessageAuthenticator()).isTrue();
        assertThat(new RadiusAuthenticator()
                        .verifyResponseMessageAuthenticator(view, new UnsafeBuffer(withMa), 4, SECRET))
                .isTrue();
        assertThat(verifiesAgainst(response, withMa)).isTrue();
        String hex = HexFormat.of().formatHex(response);
        assertThat(hex)
                .contains(HexFormat.of().formatHex("proxy-a".getBytes()))
                .contains(HexFormat.of().formatHex("proxy-b".getBytes()));
    }

    @Test
    void retransmitOfALongPendingRequestIsResubmitted() throws Exception {
        start();
        byte[] packet = request(5, false, "s-lost", 3);
        send(packet);
        Command lost = commands().get(0); // e.g. offered to a leader that died before committing
        clock[0] += Duration.ofMillis(500).toNanos();
        send(packet);
        assertThat(commands()).as("within 1 s: still in flight").isEmpty();
        clock[0] += Duration.ofSeconds(1).toNanos();
        send(packet);
        List<Command> again = commands();
        assertThat(again).as("resubmitted").hasSize(1);
        assertThat(again.get(0).exactHi()).isEqualTo(lost.exactHi());
        assertThat(stats.get(GatewayStats.Counter.RESUBMITTED)).isEqualTo(1);

        commit(lost.correlationId(), Outcome.APPLIED);
        assertThat(stats.get(GatewayStats.Counter.LATE_COMMITS)).isEqualTo(1);
        assertThat(receive()).isNull();
        commit(again.get(0).correlationId(), Outcome.DUPLICATE);
        assertThat(verifiesAgainst(receive(), packet)).isTrue();
    }

    @Test
    void newLeaderResubmitsEverythingPending() throws Exception {
        start();
        byte[] a = request(20, false, "nl-a", 1);
        byte[] b = request(21, false, "nl-b", 1);
        send(a);
        send(b);
        List<Command> first = commands();
        assertThat(first).hasSize(2);
        commit(first.get(0).correlationId(), Outcome.APPLIED); // a is done, b was lost with the old leader
        assertThat(receive()).isNotNull();

        fromCluster.write(UdpAgent.NEW_LEADER_MSG, new UnsafeBuffer(new byte[1]), 0, 1);
        work();
        List<Command> resubmitted = commands();
        assertThat(resubmitted).as("only the pending one").hasSize(1);
        assertThat(resubmitted.get(0).correlationId()).isEqualTo(first.get(1).correlationId());
        assertThat(resubmitted.get(0).exactHi()).isEqualTo(first.get(1).exactHi());
        assertThat(stats.get(GatewayStats.Counter.RESUBMITTED_ON_NEW_LEADER)).isEqualTo(1);

        commit(resubmitted.get(0).correlationId(), Outcome.APPLIED);
        assertThat(verifiesAgainst(receive(), b)).isTrue();
    }

    @Test
    void pendingRequestsTimeOutAndLateCommitsAreIgnored() throws Exception {
        start();
        byte[] packet = request(3, false, "s-late", 1);
        send(packet);
        Command c = commands().get(0);
        clock[0] += Duration.ofSeconds(11).toNanos();
        work();
        assertThat(stats.get(GatewayStats.Counter.TIMED_OUT)).isEqualTo(1);
        commit(c.correlationId(), Outcome.APPLIED);
        assertThat(stats.get(GatewayStats.Counter.LATE_COMMITS)).isEqualTo(1);
        assertThat(receive()).isNull();
        send(packet);
        assertThat(commands()).as("NAS retransmit is submitted again").hasSize(1);
    }

    @Test
    void debugResponseDelay() throws Exception {
        start(config(Duration.ofSeconds(1), 16), registry(NasClient.MessageAuthenticatorPolicy.OFF));
        send(request(4, false, "s-delay", 1));
        commit(commands().get(0).correlationId(), Outcome.APPLIED);
        assertThat(receive()).as("held back").isNull();
        clock[0] += Duration.ofSeconds(2).toNanos();
        work();
        assertThat(receive()).isNotNull();
    }

    @Test
    void sessionEventsWithoutSessionIdAreDropped() throws Exception {
        start();
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[64]);
        int length = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(4, 5)
                .uint32(40, 3)
                .finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        send(Arrays.copyOf(buffer.byteArray(), length));
        assertThat(stats.get(GatewayStats.Counter.MISSING_SESSION_ID)).isEqualTo(1);
    }

    @Test
    void fullPendingTableDrops() throws Exception {
        start(config(Duration.ZERO, 1), registry(NasClient.MessageAuthenticatorPolicy.OFF));
        send(request(1, false, "a", 1));
        send(request(2, false, "b", 1));
        assertThat(stats.get(GatewayStats.Counter.PENDING_FULL)).isEqualTo(1);
        assertThat(commands()).hasSize(1);
    }

    // ---- devices behind one NAS entry (ADR 0019) ------------------------------------------------

    static NasRegistry natRegistry() {
        return NasRegistry.of(List.of(new NasClient(
                "cloud",
                1001,
                0x7F000000,
                8,
                SECRET,
                "default",
                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                new NasClient.Identity[] {NasClient.Identity.NAS_IDENTIFIER, NasClient.Identity.CALLED_STATION_ID})));
    }

    /** An Accounting-Request from a device: {@code null} leaves an attribute out. */
    static byte[] deviceRequest(int identifier, int status, String sessionId, String nasIdentifier, String called) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, identifier).uint32(40, status);
        if (sessionId != null) {
            enc.attribute(44, sessionId);
        }
        if (nasIdentifier != null) {
            enc.attribute(32, nasIdentifier);
        }
        if (called != null) {
            enc.attribute(30, called);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, SECRET);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    @Test
    void devicesBehindOneAddressWithTheSameSessionIdAreSeparateSessions() throws Exception {
        start(config(Duration.ZERO, 1024), natRegistry());
        send(deviceRequest(1, 1, "00000001", "ap-1", null));
        send(deviceRequest(2, 1, "00000001", "ap-2", null));
        send(deviceRequest(3, 3, "00000001", "ap-1", null));
        List<Command> c = commands();
        assertThat(c).hasSize(3);
        assertThat(c.get(0).sessionHi())
                .as("other device, same Acct-Session-Id")
                .isNotEqualTo(c.get(1).sessionHi());
        assertThat(c.get(2).sessionHi()).as("same device").isEqualTo(c.get(0).sessionHi());
        assertThat(c.get(2).sessionLo()).isEqualTo(c.get(0).sessionLo());
        assertThat(c.get(0).nasId())
                .as("device scope")
                .isNotEqualTo(c.get(1).nasId())
                .isNotEqualTo(1001);
        assertThat(c.get(2).nasId()).isEqualTo(c.get(0).nasId());
        assertThat(c).allSatisfy(x -> {
            assertThat(x.nasClientId()).isEqualTo(1001);
            assertThat(x.deviceUnknown()).isFalse();
        });
        assertThat(c).extracting(Command::nasDevice).containsExactly("ap-1", "ap-2", "ap-1");
        assertThat(stats.get(GatewayStats.Counter.IDENTITY_MISSING)).isZero();
    }

    @Test
    void nextIdentityAttributeWhenTheFirstIsMissingOrEmpty() throws Exception {
        start(config(Duration.ZERO, 1024), natRegistry());
        // Open-Mesh sends an empty NAS-Identifier; the MAC in Called-Station-Id identifies the AP
        send(deviceRequest(1, 1, "s", "", "AA-BB-CC-DD-EE-FF:Guest"));
        send(deviceRequest(2, 3, "s", null, "aa:bb:cc:dd:ee:ff"));
        List<Command> c = commands();
        assertThat(c).extracting(Command::nasDevice).containsExactly("aabbccddeeff", "aabbccddeeff");
        assertThat(c.get(1).sessionHi())
                .as("one device, however the MAC is written")
                .isEqualTo(c.get(0).sessionHi());
        assertThat(c.get(1).nasId()).isEqualTo(c.get(0).nasId());
    }

    @Test
    void missingIdentityFallsBackToTheEntryAndIsFlagged() throws Exception {
        start(config(Duration.ZERO, 1024), natRegistry());
        send(deviceRequest(1, 3, "s", null, null));
        send(deviceRequest(2, 7, null, null, null)); // Accounting-On without identity
        List<Command> c = commands();
        assertThat(c).hasSize(2).allSatisfy(x -> {
            assertThat(x.nasId()).as("the entry's own scope").isEqualTo(1001);
            assertThat(x.deviceUnknown()).isTrue();
            assertThat(x.nasDevice()).isEmpty();
        });
        assertThat(stats.get(GatewayStats.Counter.IDENTITY_MISSING)).isEqualTo(2);
    }

    @Test
    void sourceIpEntriesCarryNoDevice() throws Exception {
        start();
        send(deviceRequest(1, 1, "s", "ap-1", "aa-bb-cc-dd-ee-ff"));
        Command c = commands().get(0);
        assertThat(c.nasId()).isEqualTo(1001);
        assertThat(c.nasClientId()).isEqualTo(1001);
        assertThat(c.nasDevice()).isEmpty();
        assertThat(c.deviceUnknown()).isFalse();
    }

    static NasRegistry natRegistry(NasClient.Identity... identity) {
        return NasRegistry.of(List.of(new NasClient(
                "cloud",
                1001,
                0x7F000000,
                8,
                SECRET,
                "default",
                NasClient.MessageAuthenticatorPolicy.OPTIONAL,
                identity)));
    }

    /**
     * The attribute each vendor fixture sends in every accounting packet (Start, Interim, Stop); RFC 2866 only
     * requires NAS-IP-Address <em>or</em> NAS-Identifier, and the fixtures differ in which.
     */
    static final java.util.Map<String, NasClient.Identity> EVERY_PACKET = java.util.Map.of(
            "cisco", NasClient.Identity.NAS_IP_ADDRESS,
            "huawei", NasClient.Identity.NAS_IP_ADDRESS,
            "juniper", NasClient.Identity.NAS_IDENTIFIER,
            "juniper-erx", NasClient.Identity.NAS_IP_ADDRESS,
            "meraki", NasClient.Identity.NAS_IP_ADDRESS,
            "mikrotik", NasClient.Identity.NAS_IDENTIFIER,
            "ruckus", NasClient.Identity.NAS_IP_ADDRESS);

    @Test
    void eachVendorKeepsItsSessionWithTheAttributeItSendsInEveryPacket() throws Exception {
        for (var vendor : new java.util.TreeMap<>(EVERY_PACKET).entrySet()) {
            stop();
            start(config(Duration.ZERO, 4096), natRegistry(vendor.getValue()));
            for (String event : List.of("start", "interim", "stop")) {
                send(fixture(vendor.getKey(), event));
            }
            List<Command> c = commands();
            assertThat(c)
                    .as(vendor.getKey())
                    .hasSize(3)
                    .allSatisfy(x -> assertThat(x.deviceUnknown()).isFalse());
            assertThat(c)
                    .as("%s: one device, one session", vendor.getKey())
                    .extracting(Command::sessionHi)
                    .containsOnly(c.get(0).sessionHi());
            assertThat(c).extracting(Command::nasDevice).containsOnly(c.get(0).nasDevice());
        }
        assertThat(stats.get(GatewayStats.Counter.IDENTITY_MISSING)).isZero();
        assertThat(stats.get(GatewayStats.Counter.IDENTITY_FALLBACK)).isZero();
    }

    @Test
    void anAttributeMissingFromSomePacketsSplitsTheSessionAndIsCounted() throws Exception {
        // Meraki's BSSID is in the Start's Called-Station-Id only: Interim and Stop fall back to NAS-IP-Address
        start(
                config(Duration.ZERO, 4096),
                natRegistry(NasClient.Identity.CALLED_STATION_ID, NasClient.Identity.NAS_IP_ADDRESS));
        for (String event : List.of("start", "interim", "stop")) {
            send(fixture("meraki", event));
        }
        List<Command> c = commands();
        assertThat(c).extracting(Command::nasDevice).containsExactly("e0553d000001", "10.10.0.5", "10.10.0.5");
        assertThat(c.get(1).sessionHi())
                .as("split: choose attributes sent in every packet")
                .isNotEqualTo(c.get(0).sessionHi());
        assertThat(stats.get(GatewayStats.Counter.IDENTITY_FALLBACK)).isEqualTo(2);
    }
}
