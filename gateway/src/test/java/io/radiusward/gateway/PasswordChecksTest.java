/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** PAP and CHAP against stored passwords and credential verifiers. */
class PasswordChecksTest extends HandlerFixture {

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
    void usersWithoutAUsablePasswordAreRejected() {
        main.user("nothing", List.of(), List.of())
                .user("ntOnly", List.of(item("NT-Password", ":=", "8846F7EAEE8FB117AD06BDD830B7586C")), List.of())
                .user("hashed", List.of(item("Crypt-Password", ":=", "$6$salt$x")), List.of());
        StoreAccessHandler h = handler(Map.of("main", true), Map.of());
        assertThat(pap(h, "nothing", "anything"))
                .as("no password stored and no verifier: rejected, never accepted")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "ntOnly", "password"))
                .as("NT-Password checks PAP too: the NT hash of what was typed")
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(handle(h, AccessRequestBuilder.chapSafe("hashed", "x")))
                .as("CHAP needs the cleartext password, even where the store allows CHAP")
                .isEqualTo(AccessHandler.REJECT);
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
}
