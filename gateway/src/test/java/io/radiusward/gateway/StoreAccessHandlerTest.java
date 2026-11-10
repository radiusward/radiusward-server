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
    private final Map<String, Boolean> mschap = new HashMap<>();
    private final Map<String, io.radiusward.auth.CredentialVerifier> verifiers = new HashMap<>();
    private final Map<String, String> storeVerifiers = new HashMap<>();
    private final Map<String, Boolean> chapStores = new HashMap<>();
    private EapConfig eapConfig = EapConfig.DEFAULT;

    private StoreAccessHandler handler(Map<String, Boolean> chap, Map<String, List<String>> perNas) {
        Map<String, IdentityStore> stores = new java.util.LinkedHashMap<>();
        stores.put("main", main);
        stores.put("second", second);
        return new StoreAccessHandler(
                new AuthStores(
                        stores,
                        List.of("main", "second"),
                        perNas,
                        chap,
                        Duration.ofSeconds(5),
                        1000,
                        12,
                        replyVendors,
                        mschap,
                        verifiers,
                        storeVerifiers,
                        eapConfig),
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

    private long sessionTimeout() {
        RadiusPacket reply = reply();
        int at = reply.findAttribute(27);
        return at < 0 ? -1 : reply.buffer().getInt(at + 2, java.nio.ByteOrder.BIG_ENDIAN) & 0xFFFFFFFFL;
    }

    @Test
    void loginTimeExpirationAndCountersCapTheSessionTimeout() {
        // now: Friday 2027-01-15 08:00:00 UTC
        java.util.Map<String, Long> used = new HashMap<>();
        java.util.List<java.time.Instant> since = new java.util.ArrayList<>();
        boolean[] down = {false};
        UsageCounters counters = new UsageCounters(
                List.of(
                        new UsageCounters.Counter(
                                "daily",
                                "Max-Daily-Session",
                                UsageCounters.Kind.TIME,
                                UsageCounters.Reset.DAILY,
                                "",
                                null),
                        new UsageCounters.Counter(
                                "data",
                                "Max-Monthly-Octets",
                                UsageCounters.Kind.OCTETS,
                                UsageCounters.Reset.MONTHLY,
                                "",
                                "Reply-Message")),
                (counter, user, start) -> {
                    if (down[0]) {
                        throw new java.sql.SQLException("down");
                    }
                    since.add(start);
                    return used.getOrDefault(counter.name() + ":" + user, 0L);
                },
                java.time.ZoneOffset.UTC);
        main.user(
                        "office",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Login-Time", ":=", "Wk0800-1000")),
                        List.of(item("Session-Timeout", "=", "86400")))
                .user(
                        "weekend",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Login-Time", ":=", "Sa-Su")),
                        List.of())
                .user(
                        "garbled",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Login-Time", ":=", "Xy99")),
                        List.of())
                .user(
                        "leaving",
                        List.of(
                                item("Cleartext-Password", ":=", "a"),
                                item("Expiration", ":=", "Jan 15 2027 09:00:00")),
                        List.of(item("Session-Timeout", "=", "600")))
                .user(
                        "leavingLater",
                        List.of(
                                item("Cleartext-Password", ":=", "a"),
                                item("Expiration", ":=", "Jan 15 2027 09:00:00")),
                        List.of())
                .user(
                        "metered",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Max-Daily-Session", ":=", "3600")),
                        List.of())
                .user(
                        "data",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Max-Monthly-Octets", ":=", "1000")),
                        List.of())
                .user(
                        "nonsense",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Max-Daily-Session", ":=", "lots")),
                        List.of());
        StoreAccessHandler h = handler();
        h.limits(counters, java.time.ZoneOffset.UTC);

        assertThat(pap(h, "office", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout())
                .as("until 10:00, below the user's own 86400")
                .isEqualTo(7200);
        assertThat(pap(h, "weekend", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "garbled", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "leaving", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout()).as("the user's own is shorter").isEqualTo(600);
        assertThat(pap(h, "leavingLater", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout()).as("until the expiry").isEqualTo(3600);

        used.put("daily:metered", 1000L);
        assertThat(pap(h, "metered", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout()).isEqualTo(2600);
        assertThat(since).containsExactly(java.time.Instant.parse("2027-01-15T00:00:00Z"));
        used.put("daily:metered", 3600L);
        assertThat(pap(h, "metered", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "nonsense", "a")).isEqualTo(AccessHandler.REJECT);

        used.put("data:data", 400L);
        assertThat(pap(h, "data", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout()).as("octets do not cap the time").isEqualTo(-1);
        assertThat(reply().findAttribute(18)).as("the octets left").isPositive();
        assertThat(since).last().isEqualTo(java.time.Instant.parse("2027-01-01T00:00:00Z"));

        down[0] = true;
        assertThat(pap(h, "data", "a")).as("no answer without the counter").isEqualTo(AccessHandler.DROP);
    }

    @Test
    void poolNameGetsAnAddress() {
        String[] next = {"10.0.0.7"};
        boolean[] down = {false};
        java.util.List<String> devices = new java.util.ArrayList<>();
        IpPools pools = new IpPools(
                Map.of(
                        "office",
                        new IpPools.Pool("office", List.of(), Duration.ofMinutes(5), false),
                        "guest",
                        new IpPools.Pool("guest", List.of(), Duration.ofMinutes(5), true)),
                (pool, user, device) -> {
                    if (down[0]) {
                        throw new java.sql.SQLException("down");
                    }
                    devices.add(user + "@" + device);
                    return next[0];
                });
        main.user(
                        "alice",
                        List.of(item("Cleartext-Password", ":=", "a")),
                        List.of(),
                        new UserRecord.Group("staff", List.of(item("Pool-Name", ":=", "office")), List.of()))
                .user(
                        "fixed",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Pool-Name", ":=", "office")),
                        List.of(item("Framed-IP-Address", "=", "192.0.2.1")))
                .user(
                        "guest",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Pool-Name", ":=", "guest")),
                        List.of())
                .user(
                        "lost",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Pool-Name", ":=", "nowhere")),
                        List.of());
        StoreAccessHandler h = handler();
        h.pools(pools);
        byte[] station = AccessRequestBuilder.attribute(31, "aa-bb-cc".getBytes(StandardCharsets.US_ASCII));

        assertThat(pap(h, "alice", "a", station)).isEqualTo(AccessHandler.ACCEPT);
        RadiusPacket reply = reply();
        int at = reply.findAttribute(8);
        assertThat(at).as("Framed-IP-Address").isPositive();
        assertThat(reply.buffer().getInt(at + 2, java.nio.ByteOrder.BIG_ENDIAN)).isEqualTo(0x0A000007);
        assertThat(devices).containsExactly("alice@aa-bb-cc");
        assertThat(pap(h, "fixed", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(devices).as("a fixed address is kept, the pool not asked").hasSize(1);
        assertThat(pap(h, "guest", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(devices)
                .last()
                .as("without Calling-Station-Id the user is the device")
                .isEqualTo("guest@guest");
        assertThat(pap(h, "lost", "a")).isEqualTo(AccessHandler.REJECT);

        next[0] = null;
        assertThat(pap(h, "alice", "a")).as("empty pool").isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "guest", "a")).as("empty pool that accepts").isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(8)).isNegative();
        down[0] = true;
        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.DROP);
    }

    @Test
    void rulesChangeTheReplyOrReject(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        java.nio.file.Path file = dir.resolve("rules");
        java.nio.file.Files.writeString(file, """
                if Group == staff {
                    reply Reply-Message := "staff of %{NAS-Identifier}"
                }
                if User-Name == mallory {
                    reject
                }
                """);
        main.user(
                        "alice",
                        List.of(item("Cleartext-Password", ":=", "a")),
                        List.of(),
                        new UserRecord.Group("staff", List.of(), List.of()))
                .user("mallory", List.of(item("Cleartext-Password", ":=", "a")), List.of());
        StoreAccessHandler h = handler();
        h.rules(new RulesFile(file, Duration.ZERO, name -> DICTIONARY.find(name) != null, () -> now[0]));
        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(18)).as("Reply-Message").isPositive();
        assertThat(pap(h, "mallory", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "mallory", "wrong")).isEqualTo(AccessHandler.REJECT);
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

    /** Records what the handler asks and answers with {@link #answer}. */
    static final class FakeLimits implements SessionLimits {
        int answer = GRANTED;
        int calls;
        long user;
        long device;
        int maxDevices;

        @Override
        public int reserve(long userKey, long deviceKey, int maxDevices) {
            calls++;
            this.user = userKey;
            this.device = deviceKey;
            this.maxDevices = maxDevices;
            return answer;
        }
    }

    @Test
    void simultaneousUseAsksTheClusterAfterTheCredentials() {
        UserRecord.Group pair = new UserRecord.Group("pair", List.of(item("Simultaneous-Use", ":=", "2")), List.of());
        main.user(
                        "alice",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Simultaneous-Use", ":=", "1")),
                        List.of(),
                        pair)
                .user("bob", List.of(item("Cleartext-Password", ":=", "b")), List.of(), pair)
                .user("carol", List.of(item("Cleartext-Password", ":=", "c")), List.of())
                .user(
                        "dave",
                        List.of(item("Cleartext-Password", ":=", "d"), item("Simultaneous-Use", ":=", "many")),
                        List.of());
        FakeLimits limits = new FakeLimits();
        context.sessionLimits(limits);
        StoreAccessHandler h = handler();
        byte[] station = "AA-BB-CC-DD-EE-FF".getBytes(StandardCharsets.US_ASCII);
        byte[] callingStationId = new byte[station.length + 2];
        callingStationId[0] = 31;
        callingStationId[1] = (byte) callingStationId.length;
        System.arraycopy(station, 0, callingStationId, 2, station.length);

        assertThat(pap(h, "alice", "a", callingStationId)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(limits.maxDevices)
                .as("the user's own limit wins over the group's")
                .isEqualTo(1);
        assertThat(limits.user).isEqualTo(UserKeysTest.user("ALICE"));
        assertThat(limits.device).isEqualTo(UserKeysTest.device("aa:bb:cc:dd:ee:ff"));

        assertThat(pap(h, "bob", "b")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(limits.maxDevices).as("from the group").isEqualTo(2);
        assertThat(limits.device).as("no Calling-Station-Id").isZero();

        int calls = limits.calls;
        assertThat(pap(h, "alice", "wrong")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "carol", "c")).as("no limit").isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "dave", "d")).as("an unusable limit fails closed").isEqualTo(AccessHandler.REJECT);
        assertThat(limits.calls)
                .as("only after the credentials, only with a limit")
                .isEqualTo(calls);

        limits.answer = SessionLimits.DENIED;
        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.REJECT);
        limits.answer = SessionLimits.UNAVAILABLE;
        assertThat(pap(h, "alice", "a")).as("no answer from the cluster").isEqualTo(AccessHandler.DROP);
        limits.answer = SessionLimits.UNSUPPORTED;
        assertThat(pap(h, "alice", "a")).as("before state version 6: ignored").isEqualTo(AccessHandler.ACCEPT);
    }

    static final byte[] AUTH_CHALLENGE = MsChapTest.hex("5B5D7C7D7B3F2F3E3C2C602132262628");
    static final byte[] PEER_CHALLENGE = MsChapTest.hex("21402324255E262A28295F2B3A337C7E");

    /** An MS-CHAPv2 request as a client computes it (RFC 2759), for {@code user} with {@code password}. */
    static byte[] msChap2(String user, String password) {
        byte[] name = user.getBytes(StandardCharsets.US_ASCII);
        byte[] hash = MsChap.challengeHash(PEER_CHALLENGE, AUTH_CHALLENGE, MsChap.v2UserName(name));
        byte[] response = new byte[50];
        response[0] = 7; // ident
        System.arraycopy(PEER_CHALLENGE, 0, response, 2, 16);
        System.arraycopy(MsChap.challengeResponse(hash, MsChap.ntHash(password)), 0, response, 26, 24);
        return msChapRequest(user, AUTH_CHALLENGE, 25, response);
    }

    static byte[] msChap1(String user, String password, boolean useNt) {
        byte[] challenge = MsChapTest.hex("102DB5DF085D3041");
        byte[] response = new byte[50];
        response[0] = 3;
        response[1] = (byte) (useNt ? 1 : 0);
        System.arraycopy(MsChap.challengeResponse(challenge, MsChap.ntHash(password)), 0, response, 26, 24);
        return msChapRequest(user, challenge, 1, response);
    }

    private static byte[] msChapRequest(String user, byte[] challenge, int responseType, byte[] response) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[512]);
        byte[] auth = new byte[16];
        ThreadLocalRandom.current().nextBytes(auth);
        int length = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 1)
                .authenticator(auth)
                .attribute(1, user)
                .vendorAttribute(311, 11, challenge)
                .vendorAttribute(311, responseType, response)
                .finish();
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** The values of Microsoft attribute {@code type} in the reply. */
    private List<byte[]> microsoft(int type) {
        RadiusPacket p = reply();
        List<byte[]> values = new java.util.ArrayList<>();
        for (int pos = p.attributesOffset(); pos < p.attributesEnd(); ) {
            int len = p.buffer().getByte(pos + 1) & 0xFF;
            if ((p.buffer().getByte(pos) & 0xFF) == 26
                    && p.buffer().getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN) == 311
                    && (p.buffer().getByte(pos + 6) & 0xFF) == type) {
                byte[] v = new byte[(p.buffer().getByte(pos + 7) & 0xFF) - 2];
                p.buffer().getBytes(pos + 8, v);
                values.add(v);
            }
            pos += len;
        }
        return values;
    }

    /** RFC 2548 §2.4.2 in reverse, as the NAS does it. */
    private static byte[] decryptKey(byte[] value, byte[] requestAuthenticator) throws Exception {
        java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
        byte[] plain = new byte[value.length - 2];
        byte[] previous = null;
        for (int block = 0; block < plain.length; block += 16) {
            md5.update(SECRET);
            if (previous == null) {
                md5.update(requestAuthenticator);
                md5.update(value, 0, 2);
            } else {
                md5.update(previous);
            }
            byte[] b = md5.digest();
            for (int i = 0; i < 16; i++) {
                plain[block + i] = (byte) (value[2 + block + i] ^ b[i]);
            }
            previous = Arrays.copyOfRange(value, 2 + block, 2 + block + 16);
        }
        return Arrays.copyOfRange(plain, 1, 1 + plain[0]);
    }

    @Test
    void msChapV2AcceptsWithTheAuthenticatorResponseAndMppeKeys() throws Exception {
        main.user(
                "User",
                List.of(item("NT-Password", ":=", "44EBBA8D5312B8D611474411F56989AE")),
                List.of(item("Session-Timeout", "=", "600")));
        IntHashSet mikrotik = new IntHashSet();
        mikrotik.add(14988);
        replyVendors.put("local", mikrotik); // method attributes are never filtered by vendor
        StoreAccessHandler h = handler();
        byte[] request = msChap2("User", "clientPass");
        assertThat(handle(h, request)).isEqualTo(AccessHandler.ACCEPT);
        byte[] success = microsoft(26).get(0);
        assertThat(success[0]).as("ident of the response").isEqualTo((byte) 7);
        assertThat(new String(success, 1, success.length - 1, StandardCharsets.US_ASCII))
                .isEqualTo("S=407A5589115FD0D6209F510FE9C04566932CDA56");
        byte[] auth = Arrays.copyOfRange(request, 4, 20);
        byte[] send = microsoft(16).get(0);
        byte[] recv = microsoft(17).get(0);
        assertThat(send[0] & 0x80).as("salt high bit").isNotZero();
        assertThat(new byte[] {send[0], send[1]}).isNotEqualTo(new byte[] {recv[0], recv[1]});
        assertThat(MsChapTest.hex(decryptKey(send, auth))).isEqualTo("8B7CDC149B993A1BA118CB153F56DCCB");
        byte[] master = MsChapTest.hex("FDECE3717A8C838CB388E527AE3CDD31");
        assertThat(decryptKey(recv, auth)).isEqualTo(MsChap.serverKey(master, false));
        assertThat(reply().findAttribute(27)).as("reply items too").isPositive();
    }

    @Test
    void msChapV2FailuresCarryAnErrorAndCleartextNeedsTheOptIn() {
        main.user("User", List.of(item("NT-Password", ":=", "44EBBA8D5312B8D611474411F56989AE")), List.of())
                .user("CORP\\alice", List.of(item("Cleartext-Password", ":=", "secret")), List.of());
        StoreAccessHandler h = handler();
        assertThat(handle(h, msChap2("User", "wrongPass"))).isEqualTo(AccessHandler.REJECT);
        byte[] error = microsoft(2).get(0);
        assertThat(error[0]).isEqualTo((byte) 7);
        assertThat(new String(error, 1, error.length - 1, StandardCharsets.US_ASCII))
                .isEqualTo("E=691 R=0 C=5B5D7C7D7B3F2F3E3C2C602132262628 V=3");
        assertThat(microsoft(26)).isEmpty();

        assertThat(handle(h, msChap2("nobody", "x"))).as("unknown user").isEqualTo(AccessHandler.REJECT);
        assertThat(microsoft(2)).hasSize(1);
        assertThat(handle(h, msChap2("CORP\\alice", "secret")))
                .as("cleartext without auth.store.main.mschap")
                .isEqualTo(AccessHandler.REJECT);
        mschap.put("main", true);
        StoreAccessHandler allowed = handler();
        assertThat(handle(allowed, msChap2("CORP\\alice", "secret")))
                .as("the domain is not part of the challenge hash")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(handle(allowed, msChap2("CORP\\alice", "Secret"))).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void msChapV1() throws Exception {
        main.user("bob", List.of(item("NT-Password", ":=", "8846F7EAEE8FB117AD06BDD830B7586C")), List.of());
        StoreAccessHandler h = handler();
        byte[] request = msChap1("bob", "password", true);
        assertThat(handle(h, request)).isEqualTo(AccessHandler.ACCEPT);
        byte[] keys = microsoft(12).get(0);
        assertThat(keys).hasSize(32);
        byte[] auth = Arrays.copyOfRange(request, 4, 20);
        java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5"); // RFC 2865 §5.2 in reverse
        md5.update(SECRET);
        md5.update(auth);
        byte[] b1 = md5.digest();
        md5.update(SECRET);
        md5.update(keys, 0, 16);
        byte[] b2 = md5.digest();
        byte[] plain = new byte[32];
        for (int i = 0; i < 16; i++) {
            plain[i] = (byte) (keys[i] ^ b1[i]);
            plain[16 + i] = (byte) (keys[16 + i] ^ b2[i]);
        }
        assertThat(Arrays.copyOf(plain, 8)).as("no LAN Manager key").containsOnly(0);
        assertThat(Arrays.copyOfRange(plain, 8, 24)).isEqualTo(Md4.digest(MsChap.ntHash("password")));

        assertThat(handle(h, msChap1("bob", "wrong", true))).isEqualTo(AccessHandler.REJECT);
        byte[] error = microsoft(2).get(0);
        assertThat(new String(error, 1, error.length - 1, StandardCharsets.US_ASCII))
                .isEqualTo("E=691 R=0");
        assertThat(handle(h, msChap1("bob", "password", false)))
                .as("LAN Manager response only")
                .isEqualTo(AccessHandler.REJECT);
    }

    /** A directory knowing "User" with password "clientPass", as a domain controller would check it. */
    static final class FakeVerifier implements io.radiusward.auth.CredentialVerifier {
        boolean down;
        int calls;
        String lastUser;

        @Override
        public Result verifyPassword(String userName, byte[] password) throws StoreUnavailableException {
            calls++;
            lastUser = userName;
            if (down) {
                throw new StoreUnavailableException("dc down");
            }
            return new String(password, StandardCharsets.UTF_8).equals("clientPass")
                    ? Result.accepted(null)
                    : Result.REJECTED;
        }

        @Override
        public Result verifyMsChap(String userName, byte[] challenge, byte[] ntResponse, boolean v2)
                throws StoreUnavailableException {
            calls++;
            lastUser = userName;
            if (down) {
                throw new StoreUnavailableException("dc down");
            }
            byte[] hash = MsChap.ntHash("clientPass");
            return Arrays.equals(MsChap.challengeResponse(challenge, hash), ntResponse)
                    ? Result.accepted(Md4.digest(hash))
                    : Result.REJECTED;
        }

        @Override
        public java.util.Map<String, Long> counters() {
            return java.util.Map.of("calls", (long) calls);
        }

        @Override
        public void close() {}
    }

    @Test
    void usersWithoutAPasswordAreCheckedByTheStoresVerifier() {
        FakeVerifier ad = new FakeVerifier();
        verifiers.put("ad", ad);
        storeVerifiers.put("main", "ad");
        main.user("User", List.of(), List.of(item("Session-Timeout", "=", "600")))
                .user("local", List.of(item("Cleartext-Password", ":=", "pw")), List.of());
        StoreAccessHandler h = handler();
        assertThat(pap(h, "User", "clientPass")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(ad.lastUser).isEqualTo("User");
        assertThat(reply().findAttribute(27)).as("the store's reply items").isPositive();
        assertThat(pap(h, "User", "wrong")).isEqualTo(AccessHandler.REJECT);
        int calls = ad.calls;
        assertThat(pap(h, "local", "pw"))
                .as("a local password is checked locally")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(ad.calls).isEqualTo(calls);

        byte[] v2 = msChap2("User", "clientPass");
        assertThat(handle(h, v2)).isEqualTo(AccessHandler.ACCEPT);
        byte[] success = microsoft(26).get(0);
        assertThat(new String(success, 1, success.length - 1, StandardCharsets.US_ASCII))
                .as("built from the verifier's session key")
                .isEqualTo("S=407A5589115FD0D6209F510FE9C04566932CDA56");
        assertThat(microsoft(16)).hasSize(1);
        assertThat(handle(h, msChap2("User", "other"))).isEqualTo(AccessHandler.REJECT);
        assertThat(microsoft(2)).hasSize(1);
        assertThat(handle(h, msChap1("User", "clientPass", true))).as("v1").isEqualTo(AccessHandler.ACCEPT);
        assertThat(microsoft(12)).hasSize(1);

        assertThat(handle(h, AccessRequestBuilder.chapSafe("User", "clientPass")))
                .as("CHAP needs a cleartext password")
                .isEqualTo(AccessHandler.REJECT);
        ad.down = true;
        assertThat(pap(h, "User", "clientPass"))
                .as("no answer while the directory is down")
                .isEqualTo(AccessHandler.DROP);
        var metrics = new io.radiusward.common.management.PrometheusWriter();
        h.writeMetrics(metrics, "1");
        assertThat(metrics.finish())
                .contains("radiusward_gateway_verifier_events_total{gateway=\"1\",verifier=\"ad\",event=\"calls\"} "
                        + ad.calls);
    }

    @Test
    void authTypeNamesAVerifier() {
        FakeVerifier ad = new FakeVerifier();
        verifiers.put("ad", ad);
        main.user("User", List.of(item("Cleartext-Password", ":=", "local"), item("Auth-Type", ":=", "ad")), List.of());
        StoreAccessHandler h = handler();
        assertThat(pap(h, "User", "clientPass")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "User", "local")).as("the local password is not used").isEqualTo(AccessHandler.REJECT);
        assertThat(ad.calls).isEqualTo(2);
    }

    /** An Access-Request carrying one EAP response, with a State when the conversation goes on. */
    static byte[] eapRequest(EapPacket eap, byte[] state) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 1)
                .authenticator(new byte[16]);
        enc.attribute(1, "alice");
        eap.writeTo(enc);
        if (state != null) {
            enc.attribute(24, state);
        }
        return Arrays.copyOf(buffer.byteArray(), enc.finish());
    }

    /** The reply's EAP packet and State. */
    private EapPacket replyEap() {
        return EapPacket.from(reply());
    }

    private byte[] replyState() {
        RadiusPacket r = reply();
        int at = r.findAttribute(24);
        if (at < 0) {
            return null;
        }
        byte[] state = new byte[(r.buffer().getByte(at + 1) & 0xFF) - 2];
        r.buffer().getBytes(at + 2, state);
        return state;
    }

    static EapPacket identity(int id, String name) {
        return new EapPacket(EapPacket.RESPONSE, id, EapPacket.TYPE_IDENTITY, name.getBytes(StandardCharsets.UTF_8));
    }

    /** An EAP-MD5 response to {@code challenge} (RFC 3748 §5.4). */
    static EapPacket md5Response(EapPacket challenge, String password) throws Exception {
        java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
        md5.update((byte) challenge.identifier());
        md5.update(password.getBytes(StandardCharsets.UTF_8));
        md5.update(challenge.data(), 1, challenge.data()[0] & 0xFF);
        byte[] data = new byte[17];
        data[0] = 16;
        System.arraycopy(md5.digest(), 0, data, 1, 16);
        return new EapPacket(EapPacket.RESPONSE, challenge.identifier(), EapPacket.TYPE_MD5, data);
    }

    @Test
    void eapMd5ConversationEndsInSuccessWithTheUsersReplyItems() throws Exception {
        main.user(
                "alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of(item("Filter-Id", "=", "x")));
        chapStores.put("main", true);
        StoreAccessHandler h = handler(chapStores, Map.of());

        assertThat(handle(h, eapRequest(identity(5, "alice"), null))).isEqualTo(AccessHandler.CHALLENGE);
        EapPacket challenge = replyEap();
        byte[] state = replyState();
        assertThat(challenge.code()).isEqualTo(EapPacket.REQUEST);
        assertThat(challenge.type()).isEqualTo(EapPacket.TYPE_MD5);
        assertThat(challenge.identifier()).isEqualTo(6);
        assertThat(state).hasSize(16);
        assertThat(h.eapConversations()).isEqualTo(1);

        byte[] answer = eapRequest(md5Response(challenge, "arctangent"), state);
        assertThat(handle(h, answer)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.SUCCESS);
        assertThat(replyEap().identifier()).isEqualTo(6);
        assertThat(reply().findAttribute(11)).as("Filter-Id").isPositive();
        assertThat(h.eapConversations()).isZero();

        assertThat(handle(h, answer)).as("a used State").isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.FAILURE);
    }

    @Test
    void eapFailures() throws Exception {
        main.user("alice", List.of(item("Cleartext-Password", ":=", "arctangent")), List.of())
                .user("plain", List.of(item("Cleartext-Password", ":=", "pw")), List.of());
        chapStores.put("main", true);
        StoreAccessHandler h = handler(chapStores, Map.of());

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket challenge = replyEap();
        assertThat(handle(h, eapRequest(md5Response(challenge, "wrong"), replyState())))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).as("EAP-Failure in every EAP Reject").isEqualTo(EapPacket.FAILURE);

        assertThat(handle(h, eapRequest(identity(1, "nobody"), null))).isEqualTo(AccessHandler.REJECT);
        assertThat(replyEap().code()).isEqualTo(EapPacket.FAILURE);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket c2 = replyEap();
        byte[] s2 = replyState();
        EapPacket otherId = new EapPacket(EapPacket.RESPONSE, c2.identifier() + 1, EapPacket.TYPE_MD5, new byte[17]);
        assertThat(handle(h, eapRequest(otherId, s2)))
                .as("an answer to another request")
                .isEqualTo(AccessHandler.DROP);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket c3 = replyEap();
        byte[] s3 = replyState();
        now[0] += 31_000;
        assertThat(handle(h, eapRequest(md5Response(c3, "arctangent"), s3)))
                .as("expired")
                .isEqualTo(AccessHandler.REJECT);

        handle(h, eapRequest(identity(1, "alice"), null));
        EapPacket c4 = replyEap();
        EapPacket nak = new EapPacket(EapPacket.RESPONSE, c4.identifier(), EapPacket.TYPE_NAK, new byte[] {13});
        assertThat(handle(h, eapRequest(nak, replyState())))
                .as("the peer wants EAP-TLS, which is not offered")
                .isEqualTo(AccessHandler.REJECT);

        assertThat(handle(h, eapRequest(new EapPacket(EapPacket.RESPONSE, 1, EapPacket.TYPE_MD5, new byte[17]), null)))
                .as("not Identity, no State")
                .isEqualTo(AccessHandler.REJECT);
        byte[] broken = eapRequest(identity(1, "alice"), null);
        broken[broken.length - 1 - "alice".length() - 2] = 0x7F; // EAP length no longer matches
        assertThat(handle(h, broken)).as("malformed EAP is discarded").isEqualTo(AccessHandler.DROP);

        StoreAccessHandler noCleartext = handler();
        handle(noCleartext, eapRequest(identity(1, "plain"), null));
        EapPacket c5 = replyEap();
        assertThat(handle(noCleartext, eapRequest(md5Response(c5, "pw"), replyState())))
                .as("EAP-MD5 needs the store's chap opt-in, like CHAP")
                .isEqualTo(AccessHandler.REJECT);
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

        static byte[] attribute(int type, byte[] value) {
            byte[] attribute = new byte[2 + value.length];
            attribute[0] = (byte) type;
            attribute[1] = (byte) attribute.length;
            System.arraycopy(value, 0, attribute, 2, value.length);
            return attribute;
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

        static byte[] chapSafe(String user, String password) {
            try {
                return chap(user, password);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
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
