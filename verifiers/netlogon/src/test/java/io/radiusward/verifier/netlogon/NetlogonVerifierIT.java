/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The Netlogon verifier against a Samba AD domain controller (milestone 4). */
@Epic("Authentication")
@Feature("Active Directory over Netlogon")
@Link(
        name = "ADR 0025",
        url =
                "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0025-credential-verifiers-and-ldap.md")
class NetlogonVerifierIT {

    static final String ALICE = "Alice-Passw0rd!";
    private static int netlogonPort;

    @BeforeAll
    static void domainController() throws Exception {
        SambaAd.start();
        int inside =
                EndpointMapper.port(SambaAd.endpointMapper(), NetlogonClient.NETLOGON, 1, 0, SecureChannelIT.TIMEOUT);
        netlogonPort = SambaAd.mapped(inside).getPort(); // the host reaches the container's port through a mapping
    }

    static Map<String, String> settings() {
        Map<String, String> s = new HashMap<>();
        s.put("server", SambaAd.endpointMapper().getHostString());
        s.put("server.name", "DC");
        s.put("netlogon.port", Integer.toString(netlogonPort));
        s.put("domain", "corp");
        s.put("machine.account", SambaAd.MACHINE_ACCOUNT);
        s.put("machine.password", SambaAd.MACHINE_PASSWORD);
        return s;
    }

    static CredentialVerifier verifier(Map<String, String> settings) {
        return new NetlogonVerifierProvider().create(new StoreContext("ad", settings, 2));
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] hashHash(String password) {
        return Md4.digest(NetlogonCrypto.ntHash(password));
    }

    @Test
    void msChapV2() throws Exception {
        try (CredentialVerifier v = verifier(settings())) {
            for (String name : List.of("alice", "CORP\\alice", "alice@corp.test")) {
                byte[][] r = SecureChannelIT.msChap2("alice", ALICE);
                CredentialVerifier.Result result = v.verifyMsChap(name, r[0], r[1], true);
                assertThat(result.accepted()).as(name).isTrue();
                assertThat(result.ntHashHash()).as("session key for MPPE").isEqualTo(hashHash(ALICE));
            }
            byte[][] wrong = SecureChannelIT.msChap2("alice", "wrong");
            assertThat(v.verifyMsChap("alice", wrong[0], wrong[1], true).accepted())
                    .isFalse();
            byte[][] disabled = SecureChannelIT.msChap2("carol", "Carol-Passw0rd!");
            assertThat(v.verifyMsChap("carol", disabled[0], disabled[1], true).accepted())
                    .isFalse();
            byte[][] unknown = SecureChannelIT.msChap2("nobody", "x");
            assertThat(v.verifyMsChap("nobody", unknown[0], unknown[1], true).accepted())
                    .isFalse();
            assertThat(v.verifyMsChap("OTHERDOM\\alice", wrong[0], wrong[1], true)
                            .accepted())
                    .isFalse();
        }
    }

    @Test
    void msChapV1AndPap() throws Exception {
        try (CredentialVerifier v = verifier(settings())) {
            byte[] challenge = new byte[8];
            new SecureRandom().nextBytes(challenge);
            byte[] response = NtResponse.of(challenge, NetlogonCrypto.ntHash(ALICE));
            CredentialVerifier.Result v1 = v.verifyMsChap("alice", challenge, response, false);
            assertThat(v1.accepted()).isTrue();
            assertThat(v1.ntHashHash()).isEqualTo(hashHash(ALICE));

            assertThat(v.verifyPassword("alice", utf8(ALICE)).accepted()).isTrue();
            assertThat(v.verifyPassword("alice", utf8("wrong")).accepted()).isFalse();
            assertThat(v.verifyPassword("alice", new byte[0]).accepted()).isFalse();
            assertThat(v.verifyPassword("alice", new byte[] {(byte) 0xff}).accepted())
                    .as("not UTF-8")
                    .isFalse();
            assertThat(v.verifyPassword("carol", utf8("Carol-Passw0rd!")).accepted())
                    .isFalse();
        }
    }

    @Test
    void concurrentWorkersShareABoundedPoolOfChannels() throws Exception {
        try (CredentialVerifier v = verifier(settings())) { // two channels, eight threads
            List<CompletableFuture<Integer>> runs = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                int thread = t;
                runs.add(CompletableFuture.supplyAsync(() -> {
                    int wrongDecisions = 0;
                    for (int i = 0; i < 15; i++) {
                        boolean good = (i + thread) % 2 == 0;
                        byte[][] r = SecureChannelIT.msChap2Unchecked("alice", good ? ALICE : "nope");
                        try {
                            if (v.verifyMsChap("alice", r[0], r[1], true).accepted() != good) {
                                wrongDecisions++;
                            }
                        } catch (StoreUnavailableException e) {
                            wrongDecisions++;
                        }
                    }
                    return wrongDecisions;
                }));
            }
            assertThat(runs.stream().mapToInt(CompletableFuture::join).sum()).isZero();
        }
    }

    @Test
    void anUnreachableDomainControllerOrAWrongMachinePasswordIsUnavailable() throws Exception {
        int closed;
        try (ServerSocket socket = new ServerSocket(0)) {
            closed = socket.getLocalPort();
        }
        Map<String, String> down = settings();
        down.put("netlogon.port", Integer.toString(closed));
        try (CredentialVerifier v = verifier(down)) {
            assertThatThrownBy(() -> v.verifyPassword("alice", utf8(ALICE)))
                    .isInstanceOf(StoreUnavailableException.class)
                    .hasMessageContaining("no domain controller");
        }
        Map<String, String> badMachine = settings();
        badMachine.put("machine.password", "wrong");
        try (CredentialVerifier v = verifier(badMachine)) {
            assertThatThrownBy(() -> v.verifyPassword("alice", utf8(ALICE)))
                    .isInstanceOf(StoreUnavailableException.class)
                    .hasMessageContaining("C0000022");
        }
    }

    @Test
    void failsOverPastADomainControllerThatDoesNotAnswer() throws Exception {
        Map<String, String> s = settings();
        s.put("server", "10.255.255.1 " + SambaAd.endpointMapper().getHostString()); // nothing answers at the first
        s.put("timeout", "500ms");
        try (CredentialVerifier v = verifier(s)) {
            assertThat(v.verifyPassword("alice", utf8(ALICE)).accepted()).isTrue();
            assertThat(v.counters()).containsEntry("server_failures", 1L).containsEntry("accepted", 1L);
        }
    }

    @Test
    void aFrozenDomainControllerMeansNoAnswerUntilItIsBack() throws Exception {
        Map<String, String> s = settings();
        s.put("timeout", "800ms");
        try (CredentialVerifier v = verifier(s)) {
            assertThat(v.verifyPassword("alice", utf8(ALICE)).accepted()).isTrue();
            SambaAd.pause();
            try {
                assertThatThrownBy(() -> v.verifyPassword("alice", utf8(ALICE)))
                        .isInstanceOf(StoreUnavailableException.class);
            } finally {
                SambaAd.unpause();
            }
            assertThat(v.verifyPassword("alice", utf8(ALICE)).accepted())
                    .as("a fresh channel after the outage")
                    .isTrue();
            assertThat(v.counters().get("unavailable")).isEqualTo(1L);
            assertThat(v.counters().get("channels_opened")).isGreaterThanOrEqualTo(2L);
        }
    }

    @Test
    void settingsAreChecked() {
        Map<String, String> s = settings();
        s.put("machine.account", "RADIUSWARD");
        assertThatThrownBy(() -> verifier(s)).hasMessageContaining("ends with $");
        Map<String, String> dns = settings();
        dns.put("domain", "corp.test");
        assertThatThrownBy(() -> verifier(dns)).hasMessageContaining("NetBIOS");
        Map<String, String> missing = settings();
        missing.remove("machine.password");
        assertThatThrownBy(() -> verifier(missing)).hasMessageContaining("machine.password");
        Map<String, String> nowhere = settings();
        nowhere.remove("server");
        assertThatThrownBy(() -> verifier(nowhere)).hasMessageContaining("server or dns.domain");
    }
}
