/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EapConversationsTest {

    static EapConversations.Conversation conversation(String nas, long expires) {
        EapConversations.Conversation c = new EapConversations.Conversation(nas, "alice");
        c.expires = expires;
        return c;
    }

    @Test
    void aStateIsGoodForOneResponse() {
        EapConversations table = new EapConversations(10);
        EapConversations.Conversation c = conversation("nas", 1_000);
        byte[] state = table.put(c, 0);
        assertThat(state).hasSize(16);
        assertThat(table.take(state, "other", 10))
                .as("another NAS presenting it")
                .isNull();
        byte[] again = table.put(c, 0);
        assertThat(table.take(again, "nas", 10)).isSameAs(c);
        assertThat(table.take(again, "nas", 10)).as("used").isNull();
        assertThat(table.size()).isZero();
        assertThat(table.take(new byte[5], "nas", 10)).isNull();
    }

    @Test
    void expiredConversationsAreRefusedAndSweptWhenFull() {
        EapConversations table = new EapConversations(4);
        byte[] state = table.put(conversation("nas", 100), 0);
        assertThat(table.take(state, "nas", 100)).as("expired").isNull();
        for (int i = 0; i < 4; i++) {
            assertThat(table.put(conversation("nas", 100), 0)).isNotNull();
        }
        assertThat(table.put(conversation("nas", 1_000), 50))
                .as("full, nothing expired yet")
                .isNull();
        assertThat(table.put(conversation("nas", 1_000), 200))
                .as("the expired ones are swept")
                .isNotNull();
        assertThat(table.size()).isEqualTo(1);
    }
}
