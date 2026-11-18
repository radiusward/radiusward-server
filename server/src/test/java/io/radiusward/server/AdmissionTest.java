/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.UserRecord;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** What decides after the credential: Login-Time, counters, Expire-After, pools, rules, CUI, Simultaneous-Use. */
class AdmissionTest extends HandlerFixture {

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
        h.policies(new AccessPolicies(counters, java.time.ZoneOffset.UTC, null, Totp.DEFAULT, null, null));

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
        h.policies(new AccessPolicies(null, java.time.ZoneOffset.UTC, pools, Totp.DEFAULT, null, null));
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
        h.policies(new AccessPolicies(
                null,
                java.time.ZoneOffset.UTC,
                null,
                Totp.DEFAULT,
                null,
                new RulesFile(file, Duration.ZERO, name -> DICTIONARY.find(name) != null, () -> now[0])));
        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(18)).as("Reply-Message").isPositive();
        assertThat(pap(h, "mallory", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "mallory", "wrong")).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void ipv4AndIpv6PoolsAndTheCui() {
        java.util.List<String> asked = new java.util.ArrayList<>();
        IpPools pools = new IpPools(
                Map.of(
                        "v4",
                        new IpPools.Pool("v4", List.of(), Duration.ofMinutes(5), false),
                        "pd",
                        new IpPools.Pool(
                                "pd",
                                List.of(),
                                Duration.ofMinutes(5),
                                false,
                                "Delegated-IPv6-Prefix",
                                List.of("2001:db8:100:100::/56"))),
                (pool, user, device) -> {
                    asked.add(pool.name());
                    return pool.name().equals("v4") ? "10.0.0.9" : "2001:db8:100:100::/56";
                });
        main.user(
                "alice", List.of(item("Cleartext-Password", ":=", "a"), item("Pool-Name", ":=", "v4, pd")), List.of());
        StoreAccessHandler h = handler();
        Cui cui = Cui.from(io.radiusward.common.config.Config.of(
                Map.of("auth.cui.key", "a-key-of-sixteen-chars", "auth.cui.mode", "always")));
        h.policies(new AccessPolicies(null, java.time.ZoneOffset.UTC, pools, Totp.DEFAULT, cui, null));
        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(asked).containsExactly("v4", "pd");
        RadiusPacket reply = reply();
        assertThat(reply.findAttribute(8)).as("Framed-IP-Address").isPositive();
        int pd = reply.findAttribute(123);
        assertThat(pd).as("Delegated-IPv6-Prefix").isPositive();
        assertThat(reply.buffer().getByte(pd + 3)).as("its length").isEqualTo((byte) 56);
        assertThat(reply.findAttribute(89)).as("Chargeable-User-Identity").isPositive();
    }

    @Test
    void expireAfterTheFirstLogin() {
        // now: 2027-01-15T08:00:00Z
        Map<String, java.time.Instant> first = new HashMap<>();
        boolean[] down = {false};
        UsageCounters counters =
                new UsageCounters(List.of(), (counter, user, start) -> 0, java.time.ZoneOffset.UTC, user -> {
                    if (down[0]) {
                        throw new java.sql.SQLException("down");
                    }
                    return first.get(user);
                });
        for (String user : new String[] {"fresh", "used", "over", "bad"}) {
            main.user(
                    user,
                    List.of(
                            item("Cleartext-Password", ":=", "a"),
                            item("Expire-After", ":=", user.equals("bad") ? "soon" : "86400")),
                    List.of(item("Session-Timeout", "=", "100000")));
        }
        first.put("used", java.time.Instant.parse("2027-01-15T06:00:00Z"));
        first.put("over", java.time.Instant.parse("2027-01-14T07:59:59Z"));
        StoreAccessHandler h = handler();
        h.policies(new AccessPolicies(counters, java.time.ZoneOffset.UTC, null, Totp.DEFAULT, null, null));
        assertThat(pap(h, "fresh", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout()).as("a day from now: the first login").isEqualTo(86400);
        assertThat(pap(h, "used", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(sessionTimeout()).isEqualTo(86400 - 7200);
        assertThat(pap(h, "over", "a")).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "bad", "a")).isEqualTo(AccessHandler.REJECT);
        down[0] = true;
        assertThat(pap(h, "used", "a")).isEqualTo(AccessHandler.DROP);
        StoreAccessHandler noSql = handler();
        assertThat(pap(noSql, "fresh", "a"))
                .as("no connection to find the first login")
                .isEqualTo(AccessHandler.REJECT);
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
}
