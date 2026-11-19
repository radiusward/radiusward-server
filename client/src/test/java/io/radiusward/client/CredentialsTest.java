/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.codec.AccessRequests;
import org.junit.jupiter.api.Test;

class CredentialsTest {

    @Test
    void methodsAreNamedAsOperatorsWriteThem() {
        assertThat(Credentials.Method.parse("PAP")).isEqualTo(Credentials.Method.PAP);
        assertThat(Credentials.Method.parse(" chap ")).isEqualTo(Credentials.Method.CHAP);
        for (String name : new String[] {"mschapv2", "MSCHAP2", "MS-CHAPv2"}) {
            assertThat(Credentials.Method.parse(name)).as(name).isEqualTo(Credentials.Method.MSCHAPV2);
        }
        assertThatThrownBy(() -> Credentials.Method.parse("eap"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("pap|chap|mschapv2");
    }

    @Test
    void aPapPasswordLongerThanRadiusAllowsIsRefusedWhenBuilt() {
        PacketBuilder request = PacketBuilder.accessRequest(1)
                .attribute(1, "alice")
                .password("x".repeat(AccessRequests.MAX_PASSWORD + 1))
                .secret("s");
        assertThatThrownBy(request::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at most " + AccessRequests.MAX_PASSWORD);
    }
}
