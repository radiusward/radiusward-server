/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.client.AccountingSession;
import io.radiusward.client.CoaListener;
import io.radiusward.client.CoaRequest;
import io.radiusward.client.EapLogin;
import io.radiusward.client.EapResult;
import io.radiusward.client.RadiusClient;
import io.radiusward.client.SimCard;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** EAP with the throwaway CA and SIM subscribers, and CoA and Disconnect to a NAS, as a developer tests them. */
class EmbeddedEapAndCoaIT {

    static final byte[] KI = HexFormat.of().parseHex("465b5ce8b199b49faa5f0a2ee238a6bc");
    static final byte[] OPC = HexFormat.of().parseHex("cd63cb71954a9f4e48a5994e37a02baf");

    private static void accepted(EapResult r) {
        assertThat(r.accepted()).as(r.toString()).isTrue();
        assertThat(r.serverMsk().orElseThrow())
                .as("the NAS's keys")
                .isEqualTo(r.msk().orElseThrow());
    }

    @Test
    void everyTlsBasedMethodWithTheThrowawayCa() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .eap("peap", "ttls", "teap", "tls")
                        .user("alice", "secret", "Class := gold")
                        .start();
                RadiusClient nas = radius.client()) {
            EapResult peap = nas.eap(EapLogin.peap("alice", "secret").trust(radius.ca()));
            accepted(peap);
            assertThat(peap.response().orElseThrow().string(25)).contains("gold");
            accepted(nas.eap(EapLogin.ttls("alice", "secret").trust(radius.ca())));
            accepted(nas.eap(EapLogin.teap("alice", "secret").trust(radius.ca())));
            assertThat(nas.eap(EapLogin.peap("alice", "wrong").trust(radius.ca()))
                            .rejected())
                    .isTrue();

            ClientCertificate device = radius.clientCertificate("laptop-1");
            accepted(nas.eap(
                    EapLogin.tls("laptop-1", device.key(), device.certificate()).trust(radius.ca())));
        }
    }

    @Test
    void simSubscribersWithEapSimAkaAndAkaPrime() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .eap("aka", "aka-prime", "sim")
                        .simUser("262011000000001", KI, OPC, "Reply-Message = welcome")
                        .start();
                RadiusClient nas = radius.client()) {
            SimCard card = new SimCard("262011000000001", KI, OPC);
            accepted(nas.eap(EapLogin.sim(card)));
            accepted(nas.eap(EapLogin.aka(card)));
            long sqn = card.sqn();
            accepted(nas.eap(EapLogin.akaPrime(card)));
            assertThat(card.sqn()).as("sequence numbers from the cluster").isGreaterThan(sqn);
            assertThat(nas.eap(EapLogin.aka(new SimCard("262019999999999", KI, OPC)))
                            .rejected())
                    .isTrue();
        }
    }

    @Test
    void withoutATlsMethodThereIsNoCa() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder().eap("md5").start()) {
            assertThatThrownBy(radius::ca).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void disconnectAndCoaReachTheNasOfTheUsersSessions() throws Exception {
        try (CoaListener listener = CoaListener.bind(0, EmbeddedRadiusward.DEFAULT_SECRET)
                        .answer(request ->
                                request.isDisconnect() ? CoaListener.Answer.ack() : CoaListener.Answer.nak(503));
                EmbeddedRadiusward radius =
                        EmbeddedRadiusward.builder().coaPort(listener.port()).start();
                RadiusClient acct = radius.accountingClient()) {
            assertThat(acct.send(new AccountingSession("s-1").user("alice").start())
                            .orElseThrow()
                            .isAcknowledgement())
                    .isTrue();

            List<CoaResult> coa = radius.coa("alice", "Session-Timeout = 600");
            assertThat(coa).singleElement().satisfies(r -> {
                assertThat(r.outcome()).isEqualTo(CoaResult.Outcome.NAK);
                assertThat(r.errorCause()).isEqualTo(503);
                assertThat(r.acctSessionId()).isEqualTo("s-1");
            });
            List<CoaResult> disconnect = radius.disconnect("alice");
            assertThat(disconnect)
                    .singleElement()
                    .satisfies(r -> assertThat(r.acknowledged()).isTrue());
            assertThat(listener.await(2, Duration.ofSeconds(5)))
                    .extracting(CoaRequest::isDisconnect)
                    .containsExactly(false, true);
            assertThat(radius.disconnect("nobody")).isEmpty();
        }
    }
}
