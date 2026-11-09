/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Milestones 1–2 against a Samba AD domain controller: endpoint mapper, bind, secure-channel authentication. */
class SecureChannelIT {

    static final Duration TIMEOUT = Duration.ofSeconds(5);

    @BeforeAll
    static void domainController() {
        SambaAd.start();
    }

    static int netlogonPort() throws Exception {
        return EndpointMapper.port(SambaAd.endpointMapper(), NetlogonClient.NETLOGON, 1, 0, TIMEOUT);
    }

    @Test
    void theEndpointMapperNamesNetlogonsPort() throws Exception {
        assertThat(netlogonPort()).isBetween(49152, 49155);
    }

    @Test
    void theMachineAccountEstablishesASecureChannel() throws Exception {
        try (NetlogonClient client = new NetlogonClient(SambaAd.mapped(netlogonPort()), TIMEOUT)) {
            client.authenticate(
                    "DC", SambaAd.MACHINE_ACCOUNT, SambaAd.MACHINE, NetlogonCrypto.ntHash(SambaAd.MACHINE_PASSWORD));
            assertThat(client.sessionKey()).hasSize(16);
            assertThat(client.negotiated() & NetlogonClient.NEG_AES).isNotZero();
        }
    }

    @Test
    void aWrongMachinePasswordIsRefused() throws Exception {
        try (NetlogonClient client = new NetlogonClient(SambaAd.mapped(netlogonPort()), TIMEOUT)) {
            assertThatThrownBy(() -> client.authenticate(
                            "DC", SambaAd.MACHINE_ACCOUNT, SambaAd.MACHINE, NetlogonCrypto.ntHash("wrong")))
                    .isInstanceOf(NetlogonException.class)
                    .hasMessageContaining("C0000022"); // STATUS_ACCESS_DENIED
        }
    }
}
