/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.radius;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SinkContext;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.ByteArrayOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The radius sink against fake accounting home servers (ADR 0037). */
class RadiusSinkTest {

    static final byte[] SECRET = "acct-secret".getBytes(StandardCharsets.US_ASCII);

    /** Acknowledges valid Accounting-Requests unless silent; remembers them. */
    static final class FakeAccountingServer implements AutoCloseable {
        final DatagramSocket socket = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        final List<byte[]> received = new CopyOnWriteArrayList<>();
        final AtomicBoolean silent = new AtomicBoolean();

        FakeAccountingServer() throws Exception {
            Thread t = new Thread(this::serve, "fake-accounting");
            t.setDaemon(true);
            t.start();
        }

        private void serve() {
            byte[] buffer = new byte[4096];
            RadiusAuthenticator a = new RadiusAuthenticator();
            while (!socket.isClosed()) {
                try {
                    DatagramPacket in = new DatagramPacket(buffer, buffer.length);
                    socket.receive(in);
                    byte[] request = Arrays.copyOf(buffer, in.getLength());
                    RadiusPacket p = new RadiusPacket();
                    p.wrap(new UnsafeBuffer(request), 0, request.length);
                    if (!a.verifyAccountingRequest(p, SECRET) || !a.verifyRequestMessageAuthenticator(p, SECRET)) {
                        continue;
                    }
                    received.add(request);
                    if (silent.get()) {
                        continue;
                    }
                    UnsafeBuffer out = new UnsafeBuffer(new byte[20]);
                    out.putByte(0, (byte) 5);
                    out.putByte(1, request[1]);
                    out.putShort(2, (short) 20, ByteOrder.BIG_ENDIAN);
                    a.signResponse(out, 0, 20, -1, new UnsafeBuffer(request), 4, SECRET);
                    socket.send(new DatagramPacket(out.byteArray(), 20, in.getSocketAddress()));
                } catch (Exception e) {
                    return;
                }
            }
        }

        String server() {
            return "127.0.0.1:" + socket.getLocalPort();
        }

        @Override
        public void close() {
            socket.close();
        }
    }

    private final List<AutoCloseable> closing = new ArrayList<>();

    @AfterEach
    void close() throws Exception {
        for (AutoCloseable c : closing) {
            c.close();
        }
    }

    private RadiusSink sink(Map<String, String> settings) throws Exception {
        Map<String, String> s = new HashMap<>(Map.of(
                "mode",
                "sessions+events",
                "realms",
                "partner.example",
                "secret",
                "acct-secret",
                "timeout",
                "200ms",
                "retries",
                "1"));
        s.putAll(settings);
        RadiusSink sink = new RadiusSink();
        sink.open(new SinkContext("home", 0, s, null));
        closing.add(sink);
        return sink;
    }

    static ExportEvent event(String user, String sessionId, long commitTime, byte[]... extra) {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        for (Object[] a : List.of(new Object[] {1, user}, new Object[] {44, sessionId})) {
            byte[] v = ((String) a[1]).getBytes(StandardCharsets.UTF_8);
            raw.write((Integer) a[0]);
            raw.write(2 + v.length);
            raw.writeBytes(v);
        }
        raw.writeBytes(new byte[] {40, 6, 0, 0, 0, 1}); // Acct-Status-Type Start
        for (byte[] e : extra) {
            raw.writeBytes(e);
        }
        return new ExportEvent(
                UUID.randomUUID(),
                1,
                commitTime,
                7,
                1,
                UUID.randomUUID(),
                sessionId,
                1,
                ExportEvent.EventOutcome.APPLIED,
                null,
                null,
                0,
                0,
                raw.toByteArray(),
                null);
    }

    static Batch batch(ExportEvent... events) {
        return new Batch("home", 1, 0, 10, 0, List.of(events), List.of());
    }

    static long delay(byte[] packet) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(packet), 0, packet.length);
        int at = p.findAttribute(41);
        return new UnsafeBuffer(packet).getInt(at + 2, ByteOrder.BIG_ENDIAN) & 0xFFFF_FFFFL;
    }

    @Test
    void forwardsTheRealmsEventsWithTheirDelay() throws Exception {
        FakeAccountingServer home = new FakeAccountingServer();
        closing.add(home);
        RadiusSink sink = sink(Map.of("servers", home.server()));
        long tenSecondsAgo = System.currentTimeMillis() - 10_000;
        sink.write(batch(
                event("alice@partner.example", "s-1", tenSecondsAgo, new byte[] {41, 6, 0, 0, 0, 5}),
                event("bob@other.org", "s-2", tenSecondsAgo),
                event("carol", "s-3", tenSecondsAgo),
                event("dave@PARTNER.EXAMPLE", "s-4", System.currentTimeMillis(), new byte[] {
                    80, 18, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
                })));
        assertThat(home.received).hasSize(2);
        assertThat(sink.forwardedCount()).isEqualTo(2);
        byte[] alice = home.received.stream()
                .filter(r -> new String(r, StandardCharsets.ISO_8859_1).contains("s-1"))
                .findFirst()
                .orElseThrow();
        assertThat(delay(alice)).as("5 s at the NAS + 10 s with us").isBetween(15L, 16L);
        assertThat(new String(alice, StandardCharsets.ISO_8859_1)).contains("alice@partner.example");
    }

    @Test
    void stripsTheRealmAndFailsOverToTheNextServer() throws Exception {
        FakeAccountingServer silent = new FakeAccountingServer();
        silent.silent.set(true);
        FakeAccountingServer home = new FakeAccountingServer();
        closing.add(silent);
        closing.add(home);
        RadiusSink sink = sink(Map.of("servers", silent.server() + ", " + home.server(), "strip", "true"));
        sink.write(batch(event("alice@partner.example", "s-5", System.currentTimeMillis())));
        assertThat(silent.received).as("tried twice: retries = 1").hasSize(2);
        assertThat(home.received).hasSize(1);
        String forwarded = new String(home.received.get(0), StandardCharsets.ISO_8859_1);
        assertThat(forwarded).contains("alice").doesNotContain("partner.example");
    }

    @Test
    void aBatchNoServerAcknowledgesFails() throws Exception {
        FakeAccountingServer silent = new FakeAccountingServer();
        silent.silent.set(true);
        closing.add(silent);
        RadiusSink sink = sink(Map.of("servers", silent.server()));
        assertThatThrownBy(() -> sink.write(batch(event("alice@partner.example", "s-6", 0))))
                .hasMessageContaining("no home server acknowledged");
        assertThatThrownBy(() -> sink(Map.of("servers", silent.server(), "mode", "sessions")))
                .hasMessageContaining("sessions+events");
        assertThat(RadiusSink.duration("500ms").toMillis()).isEqualTo(500);
    }
}
