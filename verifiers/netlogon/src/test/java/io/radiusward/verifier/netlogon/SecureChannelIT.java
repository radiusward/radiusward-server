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

    /** An MS-CHAPv2 exchange as a client computes it: the challenge hash and the NT response (RFC 2759). */
    static byte[][] msChap2(String user, String password) throws Exception {
        byte[] peer = new byte[16];
        byte[] authenticator = new byte[16];
        new java.security.SecureRandom().nextBytes(peer);
        new java.security.SecureRandom().nextBytes(authenticator);
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-1");
        sha.update(peer);
        sha.update(authenticator);
        sha.update(user.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] challenge = java.util.Arrays.copyOf(sha.digest(), 8);
        return new byte[][] {challenge, NtResponse.of(challenge, NetlogonCrypto.ntHash(password))};
    }

    static NetlogonClient channel() throws Exception {
        NetlogonClient client = new NetlogonClient(SambaAd.mapped(netlogonPort()), TIMEOUT);
        client.authenticate(
                "DC", SambaAd.MACHINE_ACCOUNT, SambaAd.MACHINE, NetlogonCrypto.ntHash(SambaAd.MACHINE_PASSWORD));
        return client;
    }

    @Test
    void networkLogonsOverTheSealedChannel() throws Exception {
        try (NetlogonClient client = channel()) {
            byte[][] good = msChap2("alice", "Alice-Passw0rd!");
            NetlogonClient.Logon logon;
            try {
                logon = client.samLogon("DC", "CORP", "alice", good[0], good[1]);
            } catch (java.io.IOException e) {
                java.nio.file.Files.writeString(java.nio.file.Path.of("target/samba.log"), SambaAd.logs());
                throw e;
            }
            assertThat(logon.status()).as("NTSTATUS").isZero();
            assertThat(logon.userSessionKey())
                    .as("MD4 of alice's NT hash")
                    .isEqualTo(Md4.digest(NetlogonCrypto.ntHash("Alice-Passw0rd!")));

            byte[][] wrong = msChap2("alice", "wrong");
            assertThat(client.samLogon("DC", "CORP", "alice", wrong[0], wrong[1])
                            .status())
                    .isEqualTo(NetlogonException.STATUS_WRONG_PASSWORD);
            byte[][] disabled = msChap2("carol", "Carol-Passw0rd!");
            assertThat(client.samLogon("DC", "CORP", "carol", disabled[0], disabled[1])
                            .status())
                    .isEqualTo(NetlogonException.STATUS_ACCOUNT_DISABLED);
            byte[][] unknown = msChap2("nobody", "x");
            assertThat(client.samLogon("DC", "CORP", "nobody", unknown[0], unknown[1])
                            .status())
                    .isNotZero();
            for (int i = 0; i < 5; i++) { // sequence numbers advance on both sides
                byte[][] again = msChap2("alice", "Alice-Passw0rd!");
                assertThat(client.samLogon("DC", "CORP", "alice", again[0], again[1])
                                .status())
                        .isZero();
            }
        }
    }
}
