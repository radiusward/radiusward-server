/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.client.AccountingSession;
import io.radiusward.client.RadiusClient;
import io.radiusward.export.ExportEvent;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Three members and two RADIUS servers in one JVM: what a NAS sees when members or servers stop. */
class EmbeddedClusterIT {

    @Test
    void aClusterOfThreeKeepsAcknowledgingWithOneMemberDownAndStopsWithTwo() {
        try (EmbeddedRadiusward radius =
                EmbeddedRadiusward.builder().members(3).radiusServers(2).start()) {
            assertThat(radius.authPort(0)).isNotEqualTo(radius.authPort(1));
            try (RadiusClient a = radius.accountingClient(0);
                    RadiusClient b = radius.accountingClient(1)
                            .timeout(Duration.ofSeconds(2))
                            .retries(3)) {
                assertThat(a.send(new AccountingSession("s-1").start())
                                .orElseThrow()
                                .isAcknowledgement())
                        .isTrue();

                int old = radius.stopLeader();
                int leader = radius.awaitLeader();
                assertThat(leader).as("a new leader").isNotEqualTo(old);
                assertThat(b.send(new AccountingSession("s-2").start())
                                .orElseThrow()
                                .isAcknowledgement())
                        .as("two of three members still commit")
                        .isTrue();

                radius.stopMember(leader);
                var withoutMajority = new AccountingSession("s-3").start();
                try (RadiusClient quick = radius.accountingClient(0)
                        .timeout(Duration.ofMillis(500))
                        .retries(0)) {
                    assertThat(quick.send(withoutMajority))
                            .as("one of three: no commit, no answer")
                            .isEmpty();
                }

                radius.startMember(old);
                radius.startMember(leader);
                radius.awaitLeader();
                // as a NAS does: it keeps resending until an election and the servers' reconnect are through
                try (RadiusClient patient = radius.accountingClient(1)
                        .timeout(Duration.ofSeconds(3))
                        .retries(9)) {
                    assertThat(patient.send(withoutMajority).orElseThrow().isAcknowledgement())
                            .as("the NAS resends once a majority is back")
                            .isTrue();
                }
            }
            assertThat(radius.awaitAccounting(3))
                    .extracting(ExportEvent::acctSessionId)
                    .containsExactlyInAnyOrder("s-1", "s-2", "s-3");
        }
    }

    @Test
    void aRadiusServerStopsAndComesBackOnItsPorts() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                .radiusServers(2)
                .user("alice", "secret")
                .start()) {
            int port = radius.authPort(1);
            radius.stopServer(1);
            assertThat(radius.server(1)).isNull();
            assertThatThrownBy(() -> radius.authPort(1)).isInstanceOf(IllegalStateException.class);
            try (RadiusClient other = radius.client(0)) {
                assertThat(other.pap("alice", "secret").orElseThrow().isAccept())
                        .as("the other server answers")
                        .isTrue();
            }
            radius.startServer(1);
            assertThat(radius.authPort(1)).isEqualTo(port);
            try (RadiusClient back = radius.client(1)) {
                assertThat(back.pap("alice", "secret").orElseThrow().isAccept()).isTrue();
            }
        }
    }

    @Test
    void anEvenNumberOfMembersIsRefused() {
        assertThatThrownBy(() -> EmbeddedRadiusward.builder().members(2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("1, 3, 5 or 7");
        assertThatThrownBy(() -> EmbeddedRadiusward.builder().radiusServers(0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
