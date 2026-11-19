/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.codec.RadiusCode;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** The listener plays the NAS; a RadiusClient plays the RADIUS server that sends CoA and Disconnect. */
class CoaListenerTest {

    private static RadiusClient server(CoaListener nas, String secret) {
        return RadiusClient.udp("127.0.0.1", nas.port(), secret)
                .timeout(Duration.ofMillis(300))
                .retries(0);
    }

    @Test
    void verifiedRequestsAreAcknowledgedAndKept() throws Exception {
        try (CoaListener nas = CoaListener.bind(0, "testing123");
                RadiusClient server = server(nas, "testing123")) {
            Response ack = server.send(PacketBuilder.request(RadiusCode.DISCONNECT_REQUEST, 1)
                            .attribute(1, "alice")
                            .attribute(44, "s-1"))
                    .orElseThrow();
            assertThat(ack.code()).as("verified by the client with the secret").isEqualTo(RadiusCode.DISCONNECT_ACK);
            assertThat(ack.isAcknowledgement()).isTrue();
            server.send(PacketBuilder.request(RadiusCode.COA_REQUEST, 2)
                            .attribute(1, "bob")
                            .uint32(27, 600))
                    .orElseThrow();

            var got = nas.await(2, Duration.ofSeconds(5));
            assertThat(got.get(0).isDisconnect()).isTrue();
            assertThat(got.get(0).string(1)).contains("alice");
            assertThat(got.get(1).isCoa()).isTrue();
            assertThat(got.get(1).integer(27)).hasValue(600);
            assertThat(got.get(1).from().getPort()).isPositive();
            assertThat(nas.received()).hasSize(2);
            nas.clear();
            assertThat(nas.received()).isEmpty();
        }
    }

    @Test
    void theTestDecidesTheAnswer() throws Exception {
        try (CoaListener nas = CoaListener.bind(0, "testing123")
                        .answer(r -> r.string(1).orElse("").equals("gone")
                                ? CoaListener.Answer.nak(503)
                                : CoaListener.Answer.silence());
                RadiusClient server = server(nas, "testing123")) {
            Response nak = server.send(PacketBuilder.request(RadiusCode.DISCONNECT_REQUEST, 1)
                            .attribute(1, "gone"))
                    .orElseThrow();
            assertThat(nak.code()).isEqualTo(RadiusCode.DISCONNECT_NAK);
            assertThat(nak.integer(101)).as("Error-Cause").hasValue(503);
            assertThat(server.send(
                            PacketBuilder.request(RadiusCode.COA_REQUEST, 2).attribute(1, "x")))
                    .as("silence")
                    .isEmpty();
            assertThat(nas.received()).hasSize(2);
        }
    }

    @Test
    void requestsWithAnotherSecretOrCodeAreNeitherKeptNorAnswered() throws Exception {
        try (CoaListener nas = CoaListener.bind(0, "testing123");
                RadiusClient wrong = server(nas, "another")) {
            assertThat(wrong.send(PacketBuilder.request(RadiusCode.DISCONNECT_REQUEST, 1)
                            .attribute(1, "a")))
                    .isEmpty();
            assertThat(wrong.send(PacketBuilder.accountingRequest(2).uint32(40, 1)))
                    .isEmpty();
            assertThat(nas.received()).isEmpty();
            assertThat(nas.unverified()).isEqualTo(2);
            assertThatThrownBy(() -> nas.await(1, Duration.ofMillis(100)))
                    .isInstanceOf(AssertionError.class)
                    .hasMessageContaining("got 0");
        }
    }
}
