/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.UserRecord;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Users looked up in the stores and authorized: store order, the look-up cache, check items, groups, the sweep. */
class UserDirectoryTest extends HandlerFixture {

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
    void numericNegatedAndFailingComparisons() {
        main.user("lowPort", List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port", "<", "100")), List.of())
                .user(
                        "highPort",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port", ">", "100")),
                        List.of())
                .user("upTo", List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port", "<=", "100")), List.of())
                .user("from", List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port", ">=", "100")), List.of())
                .user(
                        "notWired",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port-Type", "!~", "^Ethernet")),
                        List.of())
                .user(
                        "notThatNas",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-IP-Address", "!=", "10.0.0.1")),
                        List.of())
                .user(
                        "badPattern",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Identifier", "=~", "([unclosed")),
                        List.of())
                .user(
                        "notANumber",
                        List.of(item("Cleartext-Password", ":=", "a"), item("NAS-Port", "<", "many")),
                        List.of())
                .user(
                        "vendor",
                        List.of(item("Cleartext-Password", ":=", "a"), item("Cisco-AVPair", "==", "x")),
                        List.of())
                .user(
                        "unknown",
                        List.of(item("Cleartext-Password", ":=", "a"), item("No-Such-Attribute", "==", "x")),
                        List.of());
        StoreAccessHandler h = handler();
        byte[] port7 = AccessRequestBuilder.uint32(5, 7);
        byte[] port100 = AccessRequestBuilder.uint32(5, 100);
        byte[] port900 = AccessRequestBuilder.uint32(5, 900);
        assertThat(pap(h, "lowPort", "a", port7)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "lowPort", "a", port100)).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "highPort", "a", port900)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "highPort", "a", port100)).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "upTo", "a", port100)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "upTo", "a", port900)).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "from", "a", port100)).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "from", "a", port7)).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "lowPort", "a")).as("attribute absent: not a number").isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "notANumber", "a", port7)).as("fail closed").isEqualTo(AccessHandler.REJECT);

        assertThat(pap(h, "notWired", "a", AccessRequestBuilder.uint32(61, 19))).isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "notWired", "a", AccessRequestBuilder.uint32(61, 15))).isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "notWired", "a")).as("attribute absent").isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "notThatNas", "a", AccessRequestBuilder.ipv4(4, 10, 0, 0, 2)))
                .isEqualTo(AccessHandler.ACCEPT);
        assertThat(pap(h, "notThatNas", "a", AccessRequestBuilder.ipv4(4, 10, 0, 0, 1)))
                .isEqualTo(AccessHandler.REJECT);

        assertThat(pap(
                        h,
                        "badPattern",
                        "a",
                        AccessRequestBuilder.attribute(32, "ap-1".getBytes(StandardCharsets.UTF_8))))
                .as("an invalid pattern fails the condition")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "vendor", "a"))
                .as("vendor attributes cannot be compared")
                .isEqualTo(AccessHandler.REJECT);
        assertThat(pap(h, "unknown", "a")).isEqualTo(AccessHandler.REJECT);
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

    @Test
    void theSweepReviewsUsersAsAtLoginAndForgetsThemOnAReload() throws Exception {
        main.user("alice", List.of(), List.of(item("Session-Timeout", ":=", "600"), item("Cisco-AVPair", "+=", "a=b")));
        second.user("bob", List.of(item("Auth-Type", ":=", "Reject")), List.of());
        StoreAccessHandler h = handler();
        NasClient nas = AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF)
                .clients()
                .iterator()
                .next();
        UserDirectory.Review alice = h.review(nas, "alice", new byte[0]);
        assertThat(alice.code()).isEqualTo(AccessHandler.ACCEPT);
        assertThat(alice.found()).isTrue();
        assertThat(alice.reply())
                .extracting(AttributeItem::attribute)
                .containsExactly("Session-Timeout", "Cisco-AVPair");
        UserDirectory.Review bob = h.review(nas, "bob", new byte[0]);
        assertThat(bob.code()).as("Auth-Type := Reject").isEqualTo(AccessHandler.REJECT);
        assertThat(bob.found()).isTrue();
        assertThat(h.review(nas, "carol", new byte[0]).found()).isFalse();

        main.users.remove("alice");
        assertThat(h.review(nas, "alice", new byte[0]).code())
                .as("remembered for auth.cache.ttl")
                .isEqualTo(AccessHandler.ACCEPT);
        h.reload(stores(Map.of(), Map.of()), Duration.ZERO);
        assertThat(h.review(nas, "alice", new byte[0]).code())
                .as("a reload starts over: the user is gone")
                .isEqualTo(AccessHandler.REJECT);

        main.down = true;
        assertThat(h.review(nas, "dave", new byte[0]).code()).isEqualTo(AccessHandler.DROP);
    }
}
