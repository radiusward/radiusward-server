/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class UserKeysTest {

    static long user(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return UserKeys.user(new UnsafeBuffer(b), 0, b.length);
    }

    static long device(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return UserKeys.device(new UnsafeBuffer(b), 0, b.length);
    }

    @Test
    void userNamesMatchIgnoringAsciiCase() {
        assertThat(user("Alice@Example.COM"))
                .isEqualTo(user("alice@example.com"))
                .isNotZero();
        assertThat(user("alice")).isNotEqualTo(user("alice2"));
        assertThat(user("Ärger")).as("only ASCII is folded").isNotEqualTo(user("ärger"));
        assertThat(user("")).isZero();
    }

    @Test
    void macAddressesMatchInEveryNotation() {
        long mac = device("AA-BB-CC-DD-EE-FF");
        assertThat(device("aa:bb:cc:dd:ee:ff"))
                .isEqualTo(device("aabb.ccdd.eeff"))
                .isEqualTo(device("AABBCCDDEEFF"))
                .isEqualTo(mac)
                .isEqualTo(0xaabb_ccdd_eeffL | 1L << 48);
        assertThat(device("00:00:00:00:00:00")).as("never 0").isNotZero();
        assertThat(device("")).isZero();
    }

    @Test
    void otherStationIdsAreHashedApartFromMacs() {
        long phone = device("+4930123456789");
        assertThat(phone).isNegative().isEqualTo(device("+4930123456789"));
        assertThat(device("AA-BB-CC-DD-EE")).as("too short for a MAC").isNegative();
        assertThat(device("Station-1")).isEqualTo(device("station-1")).isNegative();
    }
}
