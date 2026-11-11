/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** A member waits for its own name to resolve to one of its addresses before it starts Aeron (ADR 0062). */
class OwnAddressTest {

    @Test
    void localNamesAndAddressesAreAcceptedAtOnce() {
        long start = System.nanoTime();
        assertThat(ClusterNode.awaitOwnAddress("localhost", 5_000)).isTrue();
        assertThat(ClusterNode.awaitOwnAddress("127.0.0.1", 5_000)).isTrue();
        assertThat(ClusterNode.awaitOwnAddress("0.0.0.0", 5_000)).isTrue();
        assertThat(System.nanoTime() - start).as("no waiting").isLessThan(2_000_000_000L);
    }

    @Test
    void anotherMachinesAddressOrAMissingNameIsWaitedForThenGivenUp() {
        long start = System.nanoTime();
        assertThat(ClusterNode.awaitOwnAddress("192.0.2.1", 700))
                .as("TEST-NET-1, never local")
                .isFalse();
        assertThat(ClusterNode.awaitOwnAddress("no-such-member.invalid", 700)).isFalse();
        assertThat(System.nanoTime() - start).as("waited for both").isGreaterThanOrEqualTo(1_400_000_000L);
    }
}
