/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** TOTP as a second factor, in challenge and append mode (ADR 0053). */
class TotpFactorTest extends HandlerFixture {

    @Test
    void totpAsksForTheCodeAfterThePassword() {
        main.user(
                        "alice",
                        List.of(
                                item("Cleartext-Password", ":=", "arctangent"),
                                item("TOTP-Secret", ":=", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
                        List.of(item("Reply-Message", "=", "in")))
                .user(
                        "broken",
                        List.of(item("Cleartext-Password", ":=", "a"), item("TOTP-Secret", ":=", "not base32!")),
                        List.of());
        Map<String, Boolean> chap = new HashMap<>(Map.of("main", true));
        StoreAccessHandler h = handler(chap, Map.of());

        assertThat(pap(h, "alice", "wrong"))
                .as("a wrong password gets no challenge")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.CHALLENGE);
        assertThat(reply().findAttribute(18)).as("the prompt").isPositive();
        byte[] state = state();
        assertThat(pap(h, "alice", totpCode(0), AccessRequestBuilder.attribute(24, state)))
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(reply().findAttribute(18)).as("the user's reply items").isPositive();
        assertThat(pap(h, "alice", totpCode(0), AccessRequestBuilder.attribute(24, state)))
                .as("the State is used up: the code is taken for the password")
                .isEqualTo(AccessHandler.REJECT);

        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.CHALLENGE);
        byte[] again = state();
        assertThat(pap(h, "alice", totpCode(0), AccessRequestBuilder.attribute(24, again)))
                .as("the code was used")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.CHALLENGE);
        byte[] third = state();
        assertThat(pap(h, "alice", "000000", AccessRequestBuilder.attribute(24, third)))
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.CHALLENGE);
        byte[] late = state();
        now[0] += 61_000;
        assertThat(pap(h, "alice", totpCode(0), AccessRequestBuilder.attribute(24, late)))
                .as("expired")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "arctangent")).isEqualTo(AccessHandler.CHALLENGE);
        byte[] other = state();
        main.user("bob", List.of(item("Cleartext-Password", ":=", "b")), List.of());
        main.user(
                "bob",
                List.of(item("Cleartext-Password", ":=", "b"), item("TOTP-Secret", ":=", "GEZDGNBVGY3TQOJQ")),
                List.of());
        now[0] += 60_000; // past the cache's lifetime
        assertThat(pap(h, "bob", totpCode(0), AccessRequestBuilder.attribute(24, other)))
                .as("another user's State")
                .isEqualTo(AccessHandler.REJECT);

        assertThat(handle(h, AccessRequestBuilder.chapSafe("alice", "arctangent")))
                .as("TOTP needs PAP")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "broken", "a")).isEqualTo(AccessHandler.REJECT);
    }

    @Test
    void totpAppendedToThePassword() {
        main.user(
                "alice",
                List.of(
                        item("Cleartext-Password", ":=", "arctangent"),
                        item("TOTP-Secret", ":=", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")),
                List.of());
        StoreAccessHandler h = handler();
        h.policies(new AccessPolicies(
                null,
                java.time.ZoneOffset.UTC,
                null,
                new Totp(true, 6, 1, Duration.ofSeconds(30), Duration.ofMinutes(1), "x"),
                null,
                null));
        assertThat(pap(h, "alice", "arctangent" + totpCode(-1))).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "alice", "arctangent" + totpCode(-1))).as("replayed").isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "arctangent" + totpCode(0))).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "alice", "wrongpass" + totpCode(1))).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "arctangent")).as("no code").isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "alice", "12345")).isEqualTo(AccessHandler.REJECT);
    }
}
