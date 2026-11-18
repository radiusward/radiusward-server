/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.radius;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.export.ExportEvent;
import io.radiusward.radius.codec.AttributeValues;
import java.util.List;
import org.junit.jupiter.api.Test;

class ForwardedRequestTest {

    private static final long NOW = 1_800_000_000_000L;

    private static ExportEvent event(String user, long commitTime, byte[]... extra) {
        return RadiusSinkTest.event(user, "s-1", commitTime, extra);
    }

    @Test
    void eventsOfTheForwardedRealmsOnly() {
        ForwardedRequest partner = new ForwardedRequest(List.of("partner.example"), false, () -> NOW);
        assertThat(partner.forwarded(event("alice@Partner.Example", NOW)))
                .as("realms compare in any case")
                .isTrue();
        assertThat(partner.forwarded(event("PARTNER.EXAMPLE\\alice", NOW)))
                .as("the realm before a backslash")
                .isTrue();
        assertThat(partner.forwarded(event("bob@other.org", NOW))).isFalse();
        assertThat(partner.forwarded(event("carol", NOW))).as("no realm").isFalse();
        ForwardedRequest any = new ForwardedRequest(List.of("*"), false, () -> NOW);
        assertThat(any.forwarded(event("bob@other.org", NOW))).isTrue();
        assertThat(any.forwarded(event("carol", NOW)))
                .as("* still needs a realm")
                .isFalse();
    }

    @Test
    void theDelaySinceTheCommitIsAddedAndTheRealmStrippedIfConfigured() {
        byte[] delayFive = {41, 6, 0, 0, 0, 5};
        byte[] messageAuthenticator = new byte[18];
        messageAuthenticator[0] = 80;
        messageAuthenticator[1] = 18;
        ExportEvent e = event("alice@partner.example", NOW - 10_000, delayFive, messageAuthenticator);

        byte[] kept = new ForwardedRequest(List.of("*"), false, () -> NOW).attributes(e);
        assertThat(AttributeValues.string(kept, 1)).isEqualTo("alice@partner.example");
        byte[] stripped = new ForwardedRequest(List.of("*"), true, () -> NOW).attributes(e);
        assertThat(AttributeValues.string(stripped, 1)).isEqualTo("alice");
        assertThat(delay(stripped))
                .as("5 s from the NAS and 10 s since the commit")
                .isEqualTo(15);
        assertThat(count(stripped, 41)).as("one Acct-Delay-Time").isEqualTo(1);
        assertThat(count(stripped, 80))
                .as("the request gets its own Message-Authenticator")
                .isZero();
        assertThat(ForwardedRequest.bare("PARTNER\\alice")).isEqualTo("alice");
        assertThat(ForwardedRequest.realm("alice")).isEmpty();
    }

    private static long delay(byte[] attributes) {
        for (int at = 0; at + 2 <= attributes.length; at += attributes[at + 1] & 0xFF) {
            if ((attributes[at] & 0xFF) == 41) {
                return ((attributes[at + 2] & 0xFFL) << 24)
                        | ((attributes[at + 3] & 0xFF) << 16)
                        | ((attributes[at + 4] & 0xFF) << 8)
                        | (attributes[at + 5] & 0xFF);
            }
        }
        return -1;
    }

    private static int count(byte[] attributes, int type) {
        int n = 0;
        for (int at = 0; at + 2 <= attributes.length; at += attributes[at + 1] & 0xFF) {
            n += (attributes[at] & 0xFF) == type ? 1 : 0;
        }
        return n;
    }
}
