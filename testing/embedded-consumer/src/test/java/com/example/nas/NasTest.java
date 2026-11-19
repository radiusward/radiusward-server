/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.example.nas;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.client.AccountingSession;
import io.radiusward.client.RadiusClient;
import io.radiusward.client.TerminateCause;
import io.radiusward.embedded.EmbeddedRadiusward;
import io.radiusward.export.ExportEvent;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** What a developer writes: a login and a session against radiusward in the test's JVM. */
class NasTest {

    @Test
    void aLoginAndASessionFromStartToStop() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .user("alice", "secret", "Class := gold")
                        .start();
                RadiusClient auth = radius.client();
                RadiusClient acct = radius.accountingClient()) {
            assertThat(auth.pap("alice", "secret").orElseThrow().string(25)).contains("gold");
            assertThat(auth.pap("alice", "wrong").orElseThrow().isReject()).isTrue();

            AccountingSession session = new AccountingSession("s-1").user("alice");
            assertThat(acct.send(session.start()).orElseThrow().isAcknowledgement()).isTrue();
            assertThat(acct.send(session.stop(Duration.ofMinutes(3), 100, 200, TerminateCause.USER_REQUEST))
                            .orElseThrow()
                            .isAcknowledgement())
                    .isTrue();
            assertThat(radius.awaitAccounting(2)).extracting(ExportEvent::statusType).containsExactly(1, 2);
            assertThat(radius.session("s-1").orElseThrow().active()).isFalse();
        }
    }
}
