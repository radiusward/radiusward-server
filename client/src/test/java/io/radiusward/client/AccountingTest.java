/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AccountingTest {

    private static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(1_780_000_000L), ZoneOffset.UTC);

    private RadiusClientTest.Server server;
    private RadiusClient client;

    @AfterEach
    void stop() throws Exception {
        if (client != null) {
            client.close();
        }
        if (server != null) {
            server.close();
        }
    }

    /** A server that acknowledges every Accounting-Request that verifies with the secret. */
    private RadiusClient client() throws Exception {
        server = new RadiusClientTest.Server(request -> {
            RadiusPacket p = wrap(request);
            return p.code() == RadiusCode.ACCOUNTING_REQUEST
                            && new RadiusAuthenticator().verifyAccountingRequest(p, SECRET)
                    ? PacketBuilder.reply(RadiusCode.ACCOUNTING_RESPONSE, request)
                            .secret(SECRET)
                            .build()
                    : null;
        });
        client = RadiusClient.udp(InetAddress.getLoopbackAddress().getHostAddress(), server.port(), "testing123")
                .timeout(Duration.ofMillis(300))
                .retries(1);
        return client;
    }

    private static RadiusPacket wrap(byte[] bytes) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return p;
    }

    private static long uint32(RadiusPacket p, int type) {
        byte[] v = p.octets(type);
        return (v[0] & 0xFFL) << 24 | (v[1] & 0xFFL) << 16 | (v[2] & 0xFFL) << 8 | v[3] & 0xFFL;
    }

    private List<RadiusPacket> received() {
        synchronized (server.received) {
            return server.received.stream().map(AccountingTest::wrap).toList();
        }
    }

    @Test
    void aSessionFromStartToStopCarriesWhatANasSends() throws Exception {
        RadiusClient c = client();
        AccountingSession s = new AccountingSession("s-1")
                .user("alice")
                .callingStationId("aa-bb-cc-dd-ee-ff")
                .calledStationId("00-11-22-33-44-55:corp")
                .nasIdentifier("ap-1")
                .nasIpAddress("192.0.2.1")
                .nasPort(7)
                .framedIpAddress("10.0.0.5")
                .multiSessionId("m-1")
                .attribute(25, "gold")
                .vendor(9, 1, "a=b")
                .clock(CLOCK);
        assertThat(c.send(s.start()))
                .hasValueSatisfying(r -> assertThat(r.isAcknowledgement()).isTrue());
        assertThat(c.send(s.interim(Duration.ofMinutes(5), 1_000_000, 4_000_000)))
                .isPresent();
        assertThat(c.send(s.stop(Duration.ofMinutes(10), 2_000_000, 8_000_000, TerminateCause.USER_REQUEST)))
                .isPresent();

        List<RadiusPacket> got = received();
        assertThat(got).extracting(p -> uint32(p, 40)).containsExactly(1L, 3L, 2L);
        RadiusPacket start = got.get(0);
        assertThat(start.string(44)).isEqualTo("s-1");
        assertThat(start.string(1)).isEqualTo("alice");
        assertThat(start.string(31)).isEqualTo("aa-bb-cc-dd-ee-ff");
        assertThat(start.string(30)).isEqualTo("00-11-22-33-44-55:corp");
        assertThat(start.string(32)).isEqualTo("ap-1");
        assertThat(start.octets(4)).containsExactly(192, 0, 2, 1);
        assertThat(uint32(start, 5)).isEqualTo(7);
        assertThat(start.octets(8)).containsExactly(10, 0, 0, 5);
        assertThat(start.string(50)).isEqualTo("m-1");
        assertThat(start.string(25)).isEqualTo("gold");
        assertThat(start.findAttribute(26)).as("Cisco-AVPair").isPositive();
        assertThat(uint32(start, 55)).isEqualTo(1_780_000_000L);
        assertThat(start.findAttribute(46)).as("no session time in a Start").isNegative();
        RadiusPacket stop = got.get(2);
        assertThat(uint32(stop, 46)).isEqualTo(600);
        assertThat(uint32(stop, 42)).isEqualTo(2_000_000);
        assertThat(uint32(stop, 43)).isEqualTo(8_000_000);
        assertThat(uint32(stop, 49)).isEqualTo(TerminateCause.USER_REQUEST.value());
    }

    @Test
    void theNasRetransmissionIsTheSameEventWithADelay() throws Exception {
        RadiusClient c = client();
        AccountingSession s = new AccountingSession("s-2").clock(CLOCK);
        AccountingEvent interim = s.interim(Duration.ofSeconds(60), 5, 6);
        c.send(interim).orElseThrow();
        c.send(interim.delay(3)).orElseThrow();
        List<RadiusPacket> got = received();
        assertThat(got.get(0).identifier())
                .as("a new identifier")
                .isNotEqualTo(got.get(1).identifier());
        assertThat(uint32(got.get(1), 55)).as("the same Event-Timestamp").isEqualTo(uint32(got.get(0), 55));
        assertThat(got.get(0).findAttribute(41)).isNegative();
        assertThat(uint32(got.get(1), 41)).isEqualTo(3);
        assertThat(interim.statusType()).isEqualTo(AccountingEvent.INTERIM_UPDATE);
    }

    @Test
    void octetsBeyondFourGibibytesGoIntoGigawords() throws Exception {
        RadiusClient c = client();
        long five = 5L << 30;
        c.send(new AccountingSession("s-3").interim(Duration.ofHours(1), five + 7, (2L << 32) + 9))
                .orElseThrow();
        RadiusPacket p = received().get(0);
        assertThat(uint32(p, 52) << 32 | uint32(p, 42)).isEqualTo(five + 7);
        assertThat(uint32(p, 53)).isEqualTo(2);
        assertThat(uint32(p, 43)).isEqualTo(9);
    }

    @Test
    void accountingOnAndOffAreNasWide() throws Exception {
        RadiusClient c = client();
        c.send(AccountingEvent.accountingOn("ap-1")).orElseThrow();
        c.send(AccountingEvent.accountingOff(null).with(4, "x")).orElseThrow();
        List<RadiusPacket> got = received();
        assertThat(uint32(got.get(0), 40)).isEqualTo(AccountingEvent.ACCOUNTING_ON);
        assertThat(got.get(0).string(32)).isEqualTo("ap-1");
        assertThat(got.get(0).findAttribute(44)).as("no session").isNegative();
        assertThat(uint32(got.get(1), 40)).isEqualTo(AccountingEvent.ACCOUNTING_OFF);
        assertThat(got.get(1).findAttribute(32)).isNegative();
    }

    @Test
    void aRecordedPacketIsReplayedWithThisClientsSecret(@TempDir Path dir) throws Exception {
        RadiusClient c = client();
        byte[] recorded = PacketBuilder.accountingRequest(9)
                .uint32(40, 1)
                .attribute(44, "rec-1")
                .messageAuthenticator()
                .secret("the recording's secret")
                .build();
        Path fixture = Files.writeString(
                dir.resolve("start.fixture"),
                "# a vendor fixture\nvendor: test\npacket: " + HexFormat.of().formatHex(recorded) + "\nexpect:\n");
        Path hex = Files.writeString(
                dir.resolve("start.hex"),
                "# pasted\n" + HexFormat.of().formatHex(recorded, 0, 10) + "\n "
                        + HexFormat.of().formatHex(recorded, 10, recorded.length) + "\n");
        assertThat(RecordedPacket.read(fixture)).isEqualTo(recorded);
        assertThat(RecordedPacket.read(hex)).isEqualTo(recorded);
        assertThat(c.replay(RecordedPacket.read(fixture)))
                .as("re-signed, so the server accepts it")
                .isPresent();
        RadiusPacket p = received().get(0);
        assertThat(p.string(44)).isEqualTo("rec-1");
        assertThat(new RadiusAuthenticator().verifyRequestMessageAuthenticator(p, SECRET))
                .isTrue();

        byte[] access = PacketBuilder.accessRequest(1).attribute(1, "x").build();
        assertThatThrownBy(() -> c.replay(access)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> c.replay(new byte[] {1, 2})).isInstanceOf(IllegalArgumentException.class);
        Path empty = Files.writeString(dir.resolve("empty.hex"), "# nothing\nzz\n");
        assertThatThrownBy(() -> RecordedPacket.read(empty)).hasMessageContaining("no packet hex");
    }

    @Test
    void mistakesAreReported() {
        assertThatThrownBy(() -> new AccountingSession("")).isInstanceOf(IllegalArgumentException.class);
        AccountingSession s = new AccountingSession("s");
        assertThatThrownBy(() -> s.nasIpAddress("not-an-address")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> s.framedIpAddress("2001:db8::1")).hasMessageContaining("IPv4");
        assertThatThrownBy(() -> s.interim(Duration.ofSeconds(-1), 0, 0)).isInstanceOf(IllegalArgumentException.class);
        AccountingEvent start = s.start();
        assertThatThrownBy(() -> start.delay(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AccountingEvent.of(1, List.of(new byte[] {1, 9})))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> start.with(1, "x".repeat(254))).isInstanceOf(IllegalArgumentException.class);
        assertThat(s.sessionId()).isEqualTo("s");
    }
}
