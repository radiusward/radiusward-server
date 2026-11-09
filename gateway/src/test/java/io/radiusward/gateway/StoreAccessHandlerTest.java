/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import org.agrona.collections.IntHashSet;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class StoreAccessHandlerTest {

    static final Dictionary DICTIONARY = DictionaryLoader.loadBundled();
    static final byte[] SECRET = AuthAgentTest.SECRET;

    /** An in-memory store counting look-ups; {@code down} makes it unavailable. */
    static final class MemoryStore implements IdentityStore {
        final Map<String, UserRecord> users = new HashMap<>();
        final AtomicInteger lookups = new AtomicInteger();
        volatile boolean down;

        MemoryStore user(
                String name, List<AttributeItem> check, List<AttributeItem> reply, UserRecord.Group... groups) {
            users.put(name, new UserRecord(name, check, reply, List.of(groups)));
            return this;
        }

        @Override
        public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
            lookups.incrementAndGet();
            if (down) {
                throw new StoreUnavailableException("down");
            }
            return Optional.ofNullable(users.get(userName));
        }

        @Override
        public void close() {}
    }

    static AttributeItem item(String attribute, String op, String value) {
        return new AttributeItem(attribute, op, value);
    }

    private final long[] now = {1_800_000_000_000L}; // 2027-01-15
    private final MemoryStore main = new MemoryStore();
    private final MemoryStore second = new MemoryStore();
    private final AccessContext context = new AccessContext();
    private final Map<String, IntHashSet> replyVendors = new HashMap<>();

    private StoreAccessHandler handler(Map<String, Boolean> chap, Map<String, List<String>> perNas) {
        Map<String, IdentityStore> stores = new java.util.LinkedHashMap<>();
        stores.put("main", main);
        stores.put("second", second);
        return new StoreAccessHandler(
                new AuthStores(
                        stores, List.of("main", "second"), perNas, chap, Duration.ofSeconds(5), 1000, 12, replyVendors),
                DICTIONARY,
                () -> now[0]);
    }

    private StoreAccessHandler handler() {
        return handler(Map.of(), Map.of());
    }

    /** Runs the handler on a PAP (or CHAP) request; returns the code. */
    private int pap(StoreAccessHandler handler, String user, String password, byte[]... extra) {
        return handle(handler, AccessRequestBuilder.pap(user, password, extra));
    }

    private int handle(StoreAccessHandler handler, byte[] request) {
        context.reset(
                new UnsafeBuffer(request),
                0,
                request.length,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                        .clients()
                        .iterator()
                        .next());
        return handler.handle(context);
    }

    /** The reply attributes the handler wrote, as a packet to inspect. */
    private RadiusPacket reply() {
        int length = context.replyAttributesLength();
        byte[] packet = new byte[RadiusPacket.HEADER_LENGTH + length];
        packet[0] = 2;
        packet[2] = (byte) (packet.length >> 8);
        packet[3] = (byte) packet.length;
        context.replyBuffer().getBytes(RadiusPacket.HEADER_LENGTH, packet, RadiusPacket.HEADER_LENGTH, length);
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(packet), 0, packet.length);
        return p;
    }

    @Test
    void papAcceptsWithReplyItemsAndRejectsAWrongPassword() {
        main.user(
                "alice",
                List.of(item("Cleartext-Password", ":=", "arctangent")),
                List.of(
                        item("Session-Timeout", "=", "3600"),
                        item("Reply-Message", "=", "Hello"),
                        item("Service-Type", "=", "Framed-User"),
                        item("Cisco-AVPair", "+=", "ip:inacl#1=permit ip any any")));
        StoreAccessHandler h = handler();
        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.ACCEPT);
        RadiusPacket reply = reply();
        assertThat(reply.findAttribute(27)).as("Session-Timeout").isPositive();
        assertThat(reply.findAttribute(18)).as("Reply-Message").isPositive();
        assertThat(reply.findAttribute(26)).as("Cisco-AVPair (vendor-specific)").isPositive();
        assertThat(pap(h, "alice", "wrong")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "nobody", "x")).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void storesAreAskedInOrderAndAnOutageIsNeverAnAnswer() {
        second.user("bob", List.of(item("Cleartext-Password", ":=", "pw")), List.of());
        StoreAccessHandler h = handler();
        assertThat(pap(h, "bob", "pw")).as("found in the second store").isEqualTo(AccessHandler.ACCEPT);
        main.down = true;
        assertThat(pap(h, "carol", "pw"))
                .as("the store that is down might know carol: no answer")
                .isEqualTo(AccessHandler.DROP);
        StoreAccessHandler fresh = handler();
        assertThat(pap(fresh, "bob", "pw")).as("another store knows bob").isEqualTo(AccessHandler.ACCEPT);
    }

    @Test
    void lookUpsAreCachedForTheTtl() {
        main.user("alice", List.of(item("Cleartext-Password", ":=", "a")), List.of());
        StoreAccessHandler h = handler();
        for (int i = 0; i < 5; i++) {
            pap(h, "alice", "a");
            pap(h, "ghost", "a");
        }
        assertThat(main.lookups).as("one each, unknown users too").hasValue(2);
        now[0] += 6_000;
        pap(h, "alice", "a");
        assertThat(main.lookups).hasValue(3);
    }

    @Test
    void authTypeExpirationAndComparisons() {
        main.user(
                        "blocked",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Auth-Type", ":=", "Reject")),
                        List.of())
                .user("mac-aabbcc", List.of(item("Auth-Type", ":=", "Accept")), List.of())
                .user(
                        "expired",
                        List.of(
                                item("Cleartext-Password", ":=", "a"),
                                item("Expiration", ":=", "Jan 01 2027 00:00:00")),
                        List.of())
                .user(
                        "valid",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Expiration", ":=", "Feb 1 2027")),
                        List.of())
                .user(
                        "badDate",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Expiration", ":=", "someday")),
                        List.of())
                .user(
                        "fromNas",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-IP-Address", "==", "10.0.0.1")),
                        List.of())
                .user(
                        "wireless",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port-Type", "=~", "^Wireless")),
                        List.of());
        StoreAccessHandler h = handler();
        assertThat(pap(h, "blocked", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "mac-aabbcc", "anything")).as("Auth-Type := Accept").isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "expired", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "valid", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "badDate", "a")).as("fail closed").isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "fromNas", "a", AccessRequestBuilder.ipv4(4, 10, 0, 0, 1)))
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "fromNas", "a", AccessRequestBuilder.ipv4(4, 10, 0, 0, 2)))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "fromNas", "a")).as("attribute absent").isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "wireless", "a", AccessRequestBuilder.uint32(61, 19)))
                .as("Wireless-802.11")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "wireless", "a", AccessRequestBuilder.uint32(61, 15)))
                .as("Ethernet")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void groupsApplyWhenTheirChecksMatch() {
        UserRecord.Group staff = new UserRecord.Group(
                "staff", List.of(item("NAS-Port-Type", "==", "Ethernet")), List.of(item("Filter-Id", "=", "staff")));
        UserRecord.Group everyone = new UserRecord.Group(
                "everyone", List.of(), List.of(item("Filter-Id", "=", "default"), item("Session-Timeout", "=", "600")));
        UserRecord.Group banned = new UserRecord.Group("banned", List.of(item("Auth-Type", ":=", "Reject")), List.of());
        main.user(
                        "alice",
                        List.of(item("Cleartext-Password", ":=", "a")),
                        List.of(item("Session-Timeout", "=", "3600")),
                        staff,
                        everyone)
                .user("mallory", List.of(item("Cleartext-Password", ":=", "a")), List.of(), banned);
        StoreAccessHandler h = handler();
        assertThat(pap(h, "alice", "a", AccessRequestBuilder.uint32(61, 15))).isEqualTo(AccessHandler.ACCEPT);
        assertThat(filterIds(reply()))
                .as("staff applies first; the user's Session-Timeout wins")
                .containsExactly("staff");
        assertThat(pap(h, "alice", "a", AccessRequestBuilder.uint32(61, 19))).isEqualTo(AccessHandler.ACCEPT);
        assertThat(filterIds(reply())).as("not Ethernet: only everyone").containsExactly("default");
        assertThat(pap(h, "mallory", "a")).isEqualTo(AccessHandler.REJECT);
    }

    private static List<String> filterIds(RadiusPacket p) {
        List<String> ids = new java.util.ArrayList<>();
        for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
            int len = p.buffer().getByte(pos + 1) & 0xFF;
            if ((p.buffer().getByte(pos) & 0xFF) == 11) {
                ids.add(p.buffer().getStringWithoutLengthUtf8(pos + 2, len - 2));
            }
            pos += len;
        }
        return ids;
    }

    @Test
    void chapOnlyWhereTheStoreAllowsCleartext() throws Exception {
        main.user("alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of());
        second.user("bob", List.of(item("Cleartext-Password", ":=", "pw")), List.of());
        StoreAccessHandler h = handler(Map.of("main", true), Map.of());
        assertThat(handle(h, AccessRequestBuilder.chap("alice", "arctangent"))).isEqualTo(AccessHandler.ACCEPT);
        assertThat(handle(h, AccessRequestBuilder.chap("alice", "wrong"))).isEqualTo(AccessHandler.REJECT);
        assertThat(handle(h, AccessRequestBuilder.chap("bob", "pw")))
                .as("store second does not allow CHAP")
                .isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void slowHashesAreCheckedOncePerTtl() {
        String stored = ShaCrypt.crypt("arctangent".getBytes(StandardCharsets.UTF_8), "$6$rounds=200000$somesalt");
        main.user("alice", List.of(item("Crypt-Password", ":=", stored)), List.of());
        StoreAccessHandler h = handler();
        long first = System.nanoTime();
        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.ACCEPT);
        long slow = System.nanoTime() - first;
        long second = System.nanoTime();
        for (int i = 0; i < 10; i++) {
            assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.ACCEPT);
        }
        assertThat(System.nanoTime() - second)
                .as("ten cached checks cost less than one hash")
                .isLessThan(slow);
        assertThat(pap(h, "alice", "wrong"))
                .as("a wrong password is never cached as right")
                .isEqualTo(AccessHandler.REJECT);
    }

    /**
     * Workers share the handler but each keeps its own caches (in its context): concurrent decisions stay correct, a
     * wrong password is never answered from a cache, and the store is asked at most once per worker and user.
     */
    @Test
    void concurrentWorkersDecideCorrectlyWithTheirOwnCaches() throws Exception {
        int users = 50;
        String slow = ShaCrypt.crypt("pw".getBytes(StandardCharsets.UTF_8), "$5$rounds=1000$salt");
        for (int u = 0; u < users; u++) {
            main.user(
                    "user" + u,
                    List.of(item(u % 2 == 0 ? "Cleartext-Password" : "Crypt-Password", ":=", u % 2 == 0 ? "pw" : slow)),
                    List.of(item("Session-Timeout", "=", Integer.toString(60 + u))));
        }
        StoreAccessHandler h = handler();
        int workers = 4;
        java.util.concurrent.atomic.AtomicInteger wrongDecisions = new java.util.concurrent.atomic.AtomicInteger();
        List<Thread> threads = new java.util.ArrayList<>();
        for (int w = 0; w < workers; w++) {
            int seed = w;
            threads.add(Thread.ofPlatform().start(() -> {
                AccessContext own = new AccessContext();
                java.util.Random random = new java.util.Random(seed);
                for (int i = 0; i < 2_000; i++) {
                    int u = random.nextInt(users);
                    boolean good = random.nextBoolean();
                    byte[] request = AccessRequestBuilder.pap("user" + u, good ? "pw" : "wrong");
                    own.reset(new UnsafeBuffer(request), 0, request.length, nas());
                    int code = h.handle(own);
                    if (code != (good ? AccessHandler.ACCEPT : AccessHandler.REJECT)) {
                        wrongDecisions.incrementAndGet();
                    }
                }
            }));
        }
        for (Thread t : threads) {
            t.join();
        }
        assertThat(wrongDecisions).hasValue(0);
        assertThat(main.lookups.get()).isBetween(users, users * workers);
    }

    private static NasClient nas() {
        return AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                .clients()
                .iterator()
                .next();
    }

    @Test
    void replyCarriesOnlyTheVendorAttributesOfTheNasEntry() {
        main.user(
                "alice",
                List.of(item("Cleartext-Password", ":=", "a")),
                List.of(
                        item("Session-Timeout", "=", "3600"),
                        item("Mikrotik-Rate-Limit", "=", "10M/20M"),
                        item("Cisco-AVPair", "+=", "sub-qos-policy-out=20M"),
                        item("Huawei-Input-Peak-Rate", "=", "10000000"),
                        item("No-Such-Attribute", "=", "x"),
                        item("Session-Timeout", "+=", "not a number")));
        IntHashSet mikrotik = new IntHashSet();
        mikrotik.add(14988);
        replyVendors.put("local", mikrotik);
        StoreAccessHandler h = handler();
        for (int i = 0; i < 3; i++) {
            assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
            RadiusPacket reply = reply();
            assertThat(reply.findAttribute(27)).as("standard attributes always").isPositive();
            assertThat(vendors(reply))
                    .as("unknown and unencodable items left out")
                    .containsExactly(14988);
        }
        assertThat(h.filtered("local")).as("Cisco and Huawei, three times").isEqualTo(6);
        assertThat(h.filtered("other")).isZero();
        var metrics = new io.radiusward.common.management.PrometheusWriter();
        h.writeMetrics(metrics, "1");
        assertThat(metrics.finish())
                .contains("radiusward_gateway_access_reply_items_filtered_total{gateway=\"1\",nas=\"local\"} 6");

        replyVendors.clear(); // no vendor set for the entry: everything that can be encoded
        StoreAccessHandler all = handler();
        assertThat(pap(all, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(vendors(reply())).containsExactly(14988, 9, 2011);
    }

    /** Vendor ids of the Vendor-Specific attributes, in order. */
    private static List<Integer> vendors(RadiusPacket p) {
        List<Integer> ids = new java.util.ArrayList<>();
        for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
            int len = p.buffer().getByte(pos + 1) & 0xFF;
            if ((p.buffer().getByte(pos) & 0xFF) == 26) {
                ids.add(p.buffer().getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN));
            }
            pos += len;
        }
        return ids;
    }

    @Test
    void bcryptAboveTheCostCeilingIsRejectedWithoutHashing() {
        String cost31 = "$2b$31$" + "DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.";
        String cost4 = org.bouncycastle.crypto.generators.OpenBSDBCrypt.generate(
                "2b", "a".getBytes(StandardCharsets.UTF_8), new byte[16], 4);
        main.user("slow", List.of(item("Crypt-Password", ":=", cost31)), List.of())
                .user("fast", List.of(item("Crypt-Password", ":=", cost4)), List.of());
        StoreAccessHandler h = handler();
        long start = System.nanoTime();
        assertThat(pap(h, "slow", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(System.nanoTime() - start).as("not 2^31 rounds").isLessThan(2_000_000_000L);
        assertThat(pap(h, "fast", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "fast", "b")).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void perNasStoresAndUnsupportedMethods() {
        main.user("alice", List.of(item("Cleartext-Password", ":=", "a")), List.of());
        StoreAccessHandler h = handler(Map.of(), Map.of("local", List.of("second")));
        assertThat(pap(h, "alice", "a")).as("NAS local asks only store second").isEqualTo(AccessHandler.REJECT);
        assertThat(handle(handler(), AccessRequestBuilder.userOnly("alice")))
                .as("no credentials")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(handle(handler(), AccessRequestBuilder.pap("", "a")))
                .as("empty User-Name")
                .isEqualTo(AccessHandler.REJECT);
    }

    /** Access-Requests for the handler tests (no Message-Authenticator: the agent checks that, not the handler). */
    static final class AccessRequestBuilder {
        static byte[] uint32(int type, long value) {
            return new byte[] {
                (byte) type, 6, (byte) (value >> 24), (byte) (value >> 16), (byte) (value >> 8), (byte) value
            };
        }

        static byte[] ipv4(int type, int a, int b, int c, int d) {
            return new byte[] {(byte) type, 6, (byte) a, (byte) b, (byte) c, (byte) d};
        }

        static byte[] pap(String user, String password, byte[]... extra) {
            byte[] request = AuthAgentTest.accessRequest(1, password, false, false);
            return withUser(request, user, extra);
        }

        static byte[] userOnly(String user) {
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
            byte[] auth = new byte[16];
            ThreadLocalRandom.current().nextBytes(auth);
            int length = new RadiusPacketEncoder()
                    .wrap(buffer, 0)
                    .header(RadiusCode.ACCESS_REQUEST, 1)
                    .authenticator(auth)
                    .attribute(1, user)
                    .finish();
            return Arrays.copyOf(buffer.byteArray(), length);
        }

        static byte[] chap(String user, String password) throws Exception {
            byte[] challenge = new byte[16];
            ThreadLocalRandom.current().nextBytes(challenge);
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update((byte) 7);
            md5.update(password.getBytes(StandardCharsets.UTF_8));
            md5.update(challenge);
            byte[] response = new byte[17];
            response[0] = 7;
            System.arraycopy(md5.digest(), 0, response, 1, 16);
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
            int length = new RadiusPacketEncoder()
                    .wrap(buffer, 0)
                    .header(RadiusCode.ACCESS_REQUEST, 1)
                    .authenticator(new byte[16])
                    .attribute(1, user)
                    .attribute(3, response)
                    .attribute(60, challenge)
                    .finish();
            return Arrays.copyOf(buffer.byteArray(), length);
        }

        /** Replaces the User-Name ("nemo") of a request built by the agent test and appends attributes. */
        private static byte[] withUser(byte[] request, String user, byte[]... extra) {
            UnsafeBuffer in = new UnsafeBuffer(request);
            RadiusPacket p = new RadiusPacket();
            p.wrap(in, 0, request.length);
            UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
            RadiusPacketEncoder enc = new RadiusPacketEncoder()
                    .wrap(buffer, 0)
                    .header(RadiusCode.ACCESS_REQUEST, 1)
                    .authenticator(in, 4);
            enc.attribute(1, user);
            for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
                int len = in.getByte(pos + 1) & 0xFF;
                if ((in.getByte(pos) & 0xFF) != 1) {
                    enc.rawAttribute(in, pos);
                }
                pos += len;
            }
            for (byte[] attribute : extra) {
                enc.rawAttribute(new UnsafeBuffer(attribute), 0);
            }
            return Arrays.copyOf(buffer.byteArray(), enc.finish());
        }
    }
}
