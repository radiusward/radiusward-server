/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.example.nas;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.client.AccountingSession;
import io.radiusward.client.RadiusClient;
import io.radiusward.embedded.EmbeddedRadiusward;
import io.radiusward.junit.Accounting;
import io.radiusward.junit.Radiusward;
import org.junit.jupiter.api.Test;

/** The same with the JUnit extension: the server and its clients as parameters, closed afterwards. */
@Radiusward(users = "alice:secret")
class ExtensionTest {

    @Test
    void aLogin(RadiusClient nas) {
        assertThat(nas.pap("alice", "secret").orElseThrow().isAccept()).isTrue();
    }

    @Test
    void aSession(EmbeddedRadiusward radius, @Accounting RadiusClient acct) {
        assertThat(acct.send(new AccountingSession("s-2").user("alice").start())
                        .orElseThrow()
                        .isAcknowledgement())
                .isTrue();
        assertThat(radius.activeSessions("alice")).hasSize(1);
    }
}
