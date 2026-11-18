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
import java.util.List;
import java.util.Map;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** The store handler's decision as a whole: PAP end to end, concurrent workers, traces, policies per request. */
class StoreAccessHandlerTest extends HandlerFixture {

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
    void aRequestKeepsItsPoliciesWhenAReloadSwapsThemMidway() {
        // the reload happens at a known point: while the pool hands out the address, before CUI is decided
        StoreAccessHandler[] handler = {null};
        AccessPolicies[] reloaded = {null};
        IpPools pools = new IpPools(
                Map.of("office", new IpPools.Pool("office", List.of(), Duration.ofMinutes(5), false)),
                (pool, user, device) -> {
                    if (reloaded[0] != null) {
                        handler[0].policies(reloaded[0]);
                        reloaded[0] = null;
                    }
                    return "10.0.0.7";
                });
        Cui cui = Cui.from(io.radiusward.common.config.Config.of(
                Map.of("auth.cui.key", "a-key-of-sixteen-chars", "auth.cui.mode", "always")));
        main.user(
                "alice", List.of(item("Cleartext-Password", ":=", "a"), item("Pool-Name", ":=", "office")), List.of());
        StoreAccessHandler h = handler();
        handler[0] = h;
        h.policies(new AccessPolicies(null, java.time.ZoneOffset.UTC, pools, Totp.DEFAULT, null, null));
        reloaded[0] = new AccessPolicies(null, java.time.ZoneOffset.UTC, pools, Totp.DEFAULT, cui, null);

        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(reloaded[0]).as("the reload happened during the request").isNull();
        assertThat(reply().findAttribute(8)).as("Framed-IP-Address").isPositive();
        assertThat(reply().findAttribute(89))
                .as("no Chargeable-User-Identity: the request began before the reload")
                .isNegative();

        assertThat(pap(h, "alice", "a")).isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(89))
                .as("the next request has the new policies")
                .isPositive();
    }

    @Test
    void tracedRequestsRecordTheirDecisions() {
        main.user(
                "alice",
                List.of(item("Cleartext-Password", ":=", "a"), item("Login-Time", ":=", "Sa")),
                List.of(),
                new UserRecord.Group("staff", List.of(), List.of()),
                new UserRecord.Group("wifi", List.of(item("NAS-Port-Type", "==", "Wireless-802.11")), List.of()));
        StoreAccessHandler h = handler();
        h.policies(new AccessPolicies(null, java.time.ZoneOffset.UTC, null, Totp.DEFAULT, null, null));
        byte[] request = AccessRequestBuilder.pap("alice", "a");
        context.reset(
                new UnsafeBuffer(request),
                0,
                request.length,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                        .clients()
                        .iterator()
                        .next());
        Tracer.Trace trace = new Tracer.Trace();
        context.trace(trace);
        assertThat(h.handle(context)).isEqualTo(AccessHandler.REJECT);
        assertThat(trace.steps.toString())
                .contains("user found in store main", "group applies: staff", "group does not apply: wifi")
                .contains("outside Login-Time Sa");
        assertThat(trace.reason).isTrue();

        context.trace(null);
        assertThat(pap(h, "nobody", "a")).isEqualTo(AccessHandler.REJECT);
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
}
