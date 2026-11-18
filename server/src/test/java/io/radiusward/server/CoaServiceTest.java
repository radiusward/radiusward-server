/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.radiusward.auth.AttributeItem;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * What the CoA service sends for a session (RFC 5176, ADR 0036): the session's identity, a NAS-IP-Address or
 * NAS-IPv6-Address when the identity names no NAS, the attributes encoded with the dictionary (vendor attributes as
 * Vendor-Specific), and where it sends them — the entry's own address, or the session's NAS address for devices behind
 * a network entry. A fake NAS on a loopback socket checks and answers each request.
 */
class CoaServiceTest {

    static final byte[] SECRET = "coa-secret".getBytes(StandardCharsets.US_ASCII);
    static final int LOOPBACK = 0x7F000001;
    static final byte[] LOOPBACK6 = new byte[16];

    static {
        LOOPBACK6[15] = 1;
    }

    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final List<AutoCloseable> open = new ArrayList<>();
    private DynamicAuthorization sender;
    private DatagramChannel nas;

    @AfterEach
    void close() throws Exception {
        if (sender != null) {
            sender.onClose();
        }
        for (AutoCloseable c : open) {
            c.close();
        }
    }

    /** A fake NAS on {@code host} and a CoA service that sends from {@code host} to the NAS's port. */
    private CoaService service(String host, NasClient... clients) throws Exception {
        nas = DatagramChannel.open().bind(new InetSocketAddress(host, 0));
        nas.configureBlocking(false);
        open.add(nas);
        int port = ((InetSocketAddress) nas.getLocalAddress()).getPort();
        Map<String, CoaConfig.Target> targets = new java.util.HashMap<>();
        for (NasClient c : clients) {
            targets.put(c.name(), new CoaConfig.Target(null, port, null)); // the address comes from the entry
        }
        CoaConfig config = new CoaConfig(true, Duration.ofMillis(50), 1, null, targets);
        sender = new DynamicAuthorization(config, host, null);
        sender.onStart();
        return new CoaService(
                config,
                NasRegistry.of(List.of(clients)),
                new ClusterQueries(),
                sender,
                HandlerFixture.DICTIONARY,
                new RadsecLink(new NasClient[0]),
                Map.of(),
                Map.of(),
                null);
    }

    private static NasClient single(String name, int id) {
        return NasClient.builder(name, id)
                .network(LOOPBACK, 32)
                .secret(SECRET)
                .messageAuthenticator(NasClient.MessageAuthenticatorPolicy.OFF)
                .build();
    }

    private static NasClient network(String name, int id) {
        return NasClient.builder(name, id)
                .network(0x7F000000, 8)
                .secret(SECRET)
                .messageAuthenticator(NasClient.MessageAuthenticatorPolicy.OFF)
                .identity(NasClient.Identity.NAS_IP_ADDRESS)
                .build();
    }

    private static NasClient ipv6(String name, int id, int prefixLength) {
        return new NasClient(
                name,
                id,
                0,
                prefixLength,
                SECRET,
                "default",
                NasClient.MessageAuthenticatorPolicy.OFF,
                new NasClient.Identity[0],
                0,
                NasClient.MessageAuthenticatorPolicy.REQUIRED,
                LOOPBACK6);
    }

    private static boolean ipv6Loopback() {
        try (DatagramChannel c = DatagramChannel.open()) {
            c.bind(new InetSocketAddress("::1", 0));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** Identity attributes: type, then the value. */
    private static byte[] attrs(Object... typeValue) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < typeValue.length; i += 2) {
            byte[] v = typeValue[i + 1] instanceof byte[] b
                    ? b
                    : ((String) typeValue[i + 1]).getBytes(StandardCharsets.UTF_8);
            out.write((Integer) typeValue[i]);
            out.write(2 + v.length);
            out.writeBytes(v);
        }
        return out.toByteArray();
    }

    private static ClusterQueries.Session session(int nasId, byte[] identity) {
        return new ClusterQueries.Session(1, 2, nasId, 3, 0, 0, true, identity);
    }

    /** The next request at the fake NAS, its authenticators checked; {@code null} if none came. */
    private Received receive() throws Exception {
        ByteBuffer in = ByteBuffer.allocate(4096);
        for (int i = 0; i < 200; i++) {
            sender.doWork();
            in.clear();
            InetSocketAddress from = (InetSocketAddress) nas.receive(in);
            if (from != null) {
                byte[] bytes = Arrays.copyOf(in.array(), in.position());
                RadiusPacket p = new RadiusPacket();
                p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
                assertThat(authenticator.verifyAccountingRequest(p, SECRET)).isTrue();
                return new Received(bytes, from);
            }
            Thread.sleep(2);
        }
        return null;
    }

    record Received(byte[] bytes, InetSocketAddress from) {

        /** The attributes after the header, without Message-Authenticator. */
        byte[] attributes() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int at = 20; at + 2 <= bytes.length; at += bytes[at + 1] & 0xFF) {
                if (bytes[at] != 80) {
                    out.write(bytes, at, bytes[at + 1] & 0xFF);
                }
            }
            return out.toByteArray();
        }
    }

    private void answer(Received r, int code) throws Exception {
        UnsafeBuffer out = new UnsafeBuffer(new byte[20]);
        out.putByte(0, (byte) code);
        out.putByte(1, r.bytes()[1]);
        out.putShort(2, (short) 20, ByteOrder.BIG_ENDIAN);
        authenticator.signResponse(out, 0, 20, -1, new UnsafeBuffer(r.bytes()), 4, SECRET);
        nas.send(ByteBuffer.wrap(out.byteArray()), r.from());
    }

    private DynamicAuthorization.Result await(CompletableFuture<DynamicAuthorization.Result> f) throws Exception {
        for (int i = 0; i < 500 && !f.isDone(); i++) {
            sender.doWork();
            Thread.sleep(2);
        }
        return f.getNow(null);
    }

    @Test
    void vendorAttributesAreSentAsVendorSpecificAfterTheIdentityAndTheNasAddress() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        byte[] identity = attrs(44, "s-1", 1, "alice");
        CompletableFuture<DynamicAuthorization.Result> f = coa.send(
                session(1, identity),
                DynamicAuthorization.COA_REQUEST,
                List.of(
                        new AttributeItem("Session-Timeout", ":=", "3600"),
                        new AttributeItem("Cisco-AVPair", ":=", "subscriber:command=reauthenticate")));
        Received r = receive();
        assertThat(r).isNotNull();
        assertThat(r.bytes()[0]).isEqualTo((byte) DynamicAuthorization.COA_REQUEST);
        byte[] value = "subscriber:command=reauthenticate".getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream vsa = new ByteArrayOutputStream();
        vsa.writeBytes(new byte[] {26, (byte) (8 + value.length), 0, 0, 0, 9, 1, (byte) (2 + value.length)});
        vsa.writeBytes(value);
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.writeBytes(identity);
        expected.writeBytes(new byte[] {4, 6, 127, 0, 0, 1}); // RFC 5176 §3: the identity named no NAS
        expected.writeBytes(new byte[] {27, 6, 0, 0, 0x0E, 0x10});
        expected.writeBytes(vsa.toByteArray());
        assertThat(r.attributes()).isEqualTo(expected.toByteArray());
        answer(r, DynamicAuthorization.COA_ACK);
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void aSessionThatNamesItsNasGetsNoAddedNasAttribute() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        byte[] identity = attrs(44, "s-1", 32, "ap-7");
        coa.send(session(1, identity), DynamicAuthorization.DISCONNECT_REQUEST, List.of());
        assertThat(receive().attributes()).isEqualTo(identity);
    }

    @Test
    void aDeviceBehindANetworkEntryIsFoundAndAddressedByItsNasIpAddress() throws Exception {
        CoaService coa = service("127.0.0.1", network("campus", 2));
        byte[] identity = attrs(4, new byte[] {127, 0, 0, 1}, 44, "s-9");
        ClusterQueries.Session s = session(77, identity); // the device's own id, not an entry's
        assertThat(coa.nasOf(s).name()).isEqualTo("campus");
        CompletableFuture<DynamicAuthorization.Result> f =
                coa.send(s, DynamicAuthorization.DISCONNECT_REQUEST, List.of());
        Received r = receive();
        assertThat(r.from().getAddress()).isEqualTo(InetAddress.getByName("127.0.0.1"));
        assertThat(r.attributes()).isEqualTo(identity);
        answer(r, DynamicAuthorization.DISCONNECT_ACK);
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void aSessionWithoutIdentityOrNasIsUnreachable() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        assertThat(coa.send(session(1, new byte[0]), DynamicAuthorization.DISCONNECT_REQUEST, List.of())
                        .get()
                        .outcome())
                .isEqualTo(DynamicAuthorization.Outcome.UNREACHABLE);
        ClusterQueries.Session unknown = session(5, attrs(44, "s-1", 4, new byte[] {10, 9, 9, 9}));
        assertThat(coa.nasOf(unknown)).isNull();
        assertThat(coa.send(unknown, DynamicAuthorization.DISCONNECT_REQUEST, List.of())
                        .get()
                        .outcome())
                .isEqualTo(DynamicAuthorization.Outcome.UNREACHABLE);
        ClusterQueries.Session malformed = session(5, new byte[] {44, 1, 0});
        assertThat(coa.nasOf(malformed)).isNull();
    }

    @Test
    void aNasThatDoesNotAnswerTimesOut() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        CompletableFuture<DynamicAuthorization.Result> f =
                coa.send(session(1, attrs(44, "s-1")), DynamicAuthorization.DISCONNECT_REQUEST, List.of());
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.TIMEOUT);
    }

    @Test
    void valuesTooLongForOneAttributeAndUnknownAttributesAreRefused() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        ClusterQueries.Session s = session(1, attrs(44, "s-1"));
        assertRefused(coa.send(s, DynamicAuthorization.COA_REQUEST, List.of(item("Filter-Id", 254))));
        assertRefused(coa.send(s, DynamicAuthorization.COA_REQUEST, List.of(item("Cisco-AVPair", 248))));
        assertRefused(
                coa.send(s, DynamicAuthorization.COA_REQUEST, List.of(new AttributeItem("No-Such-Attr", ":=", "1"))));
        assertThatThrownBy(() -> coa.changeUser("alice", List.of(new AttributeItem("No-Such-Attr", ":=", "1"))))
                .as("refused before any session is asked for")
                .isInstanceOf(IllegalArgumentException.class);
        // the longest values that fit are sent
        coa.send(s, DynamicAuthorization.COA_REQUEST, List.of(item("Filter-Id", 253), item("Cisco-AVPair", 247)));
        assertThat(receive().bytes().length).isEqualTo(20 + 5 + 6 + 255 + 255 + 18);
    }

    private static AttributeItem item(String name, int length) {
        return new AttributeItem(name, ":=", "x".repeat(length));
    }

    private static void assertRefused(CompletableFuture<DynamicAuthorization.Result> f) {
        assertThatThrownBy(f::get)
                .isInstanceOf(ExecutionException.class)
                .hasCauseInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void sessionsAreAddressedByUserWhenTheEntryTellsDevicesApart() throws Exception {
        CoaService coa = service("127.0.0.1", network("campus", 2));
        assertThatThrownBy(() -> coa.toSession("campus", "s-1", List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("address its sessions by user");
        assertThatThrownBy(() -> coa.toSession("nowhere", "s-1", List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("no NAS entry nowhere");
    }

    @Test
    void aRelayedRequestWithoutUserGoesToTheEntryOfItsNasIpAddress() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        byte[] request = attrs(4, new byte[] {127, 0, 0, 1}, 44, "s-1");
        CompletableFuture<DynamicAuthorization.Result> f = coa.relay(DynamicAuthorization.DISCONNECT_REQUEST, request);
        Received r = receive();
        assertThat(r.attributes()).isEqualTo(request);
        answer(r, DynamicAuthorization.DISCONNECT_ACK);
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);

        assertThat(coa.relay(DynamicAuthorization.DISCONNECT_REQUEST, attrs(44, "s-1")))
                .as("no NAS address")
                .isNull();
        assertThat(coa.relay(DynamicAuthorization.DISCONNECT_REQUEST, attrs(4, new byte[] {10, 0, 0, 1})))
                .as("no entry")
                .isNull();
        assertThat(coa.relay(DynamicAuthorization.DISCONNECT_REQUEST, attrs(4, new byte[] {127, 0, 0})))
                .as("not an IPv4 address")
                .isNull();
    }

    @Test
    void aRelayedRequestIsNotSentToADeviceBehindANetworkEntry() throws Exception {
        CoaService coa = service("127.0.0.1", network("campus", 2));
        assertThat(coa.relay(DynamicAuthorization.DISCONNECT_REQUEST, attrs(4, new byte[] {127, 0, 0, 1})))
                .isNull();
    }

    @Test
    void attributesAreReadUpToTheFirstMalformedOne() {
        assertThat(CoaService.raw(attrs(1, "bob", 44, "s-2"), 44)).isEqualTo("s-2".getBytes(StandardCharsets.UTF_8));
        assertThat(CoaService.raw(attrs(1, "bob"), 44)).isNull();
        assertThat(CoaService.raw(new byte[] {1, 1, 44, 3, 'x'}, 44))
                .as("length below 2")
                .isNull();
        assertThat(CoaService.raw(new byte[] {44, 9, 'x'}, 44))
                .as("past the end")
                .isNull();
    }

    @Test
    void anIpv6EntryIsAddressedAtItsOwnAddressWithANasIpv6Address() throws Exception {
        assumeTrue(ipv6Loopback(), "no IPv6 loopback");
        CoaService coa = service("::1", ipv6("ap6", 3, 128));
        byte[] identity = attrs(44, "s-6");
        CompletableFuture<DynamicAuthorization.Result> f =
                coa.send(session(3, identity), DynamicAuthorization.DISCONNECT_REQUEST, List.of());
        Received r = receive();
        assertThat(r.from().getAddress()).isEqualTo(InetAddress.getByName("::1"));
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.writeBytes(identity);
        expected.write(95);
        expected.write(18);
        expected.writeBytes(LOOPBACK6);
        assertThat(r.attributes()).isEqualTo(expected.toByteArray());
        answer(r, DynamicAuthorization.DISCONNECT_ACK);
        assertThat(await(f).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);

        CompletableFuture<DynamicAuthorization.Result> relayed =
                coa.relay(DynamicAuthorization.DISCONNECT_REQUEST, attrs(95, LOOPBACK6));
        assertThat(relayed).as("relayed by NAS-IPv6-Address").isNotNull();
        answer(receive(), DynamicAuthorization.DISCONNECT_ACK);
        assertThat(await(relayed).outcome()).isEqualTo(DynamicAuthorization.Outcome.ACK);
    }

    @Test
    void aDeviceBehindAnIpv6NetworkEntryIsAddressedByItsNasIpv6Address() throws Exception {
        assumeTrue(ipv6Loopback(), "no IPv6 loopback");
        CoaService coa = service("::1", ipv6("campus6", 4, 64));
        byte[] identity = attrs(95, LOOPBACK6, 44, "s-7");
        ClusterQueries.Session s = session(88, identity);
        assertThat(coa.nasOf(s).name()).isEqualTo("campus6");
        coa.send(s, DynamicAuthorization.DISCONNECT_REQUEST, List.of());
        Received r = receive();
        assertThat(r.from().getAddress()).isEqualTo(InetAddress.getByName("::1"));
        assertThat(r.attributes()).isEqualTo(identity);
    }

    @Test
    void simultaneousUseDisconnectsAreCounted() throws Exception {
        CoaService coa = service("127.0.0.1", single("ap", 1));
        coa.countSimultaneousUse(true);
        coa.countSimultaneousUse(true);
        coa.countSimultaneousUse(false);
        PrometheusWriter w = new PrometheusWriter();
        coa.writeMetrics(w, "g1");
        String text = w.finish();
        PrometheusWriter.validate(text);
        assertThat(text)
                .contains(
                        "radiusward_server_simultaneous_use_disconnects_total{server=\"g1\",result=\"acknowledged\"} 2")
                .contains("radiusward_server_simultaneous_use_disconnects_total{server=\"g1\",result=\"failed\"} 1");
        assertThat(coa.config().enabled()).isTrue();
        assertThat(coa.queries()).isNotNull();
    }
}
