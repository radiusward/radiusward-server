/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class MsChapAuthenticatorTest {

    private static RadiusPacket packet(byte[] bytes) {
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        return packet;
    }

    @Test
    void wellFormedRequestsAreParsed() {
        MsChapAuthenticator.Request v2 = MsChapAuthenticator.request(
                packet(StoreAccessHandlerTest.msChap2("User", "clientPass")), AccessRequests.METHOD_MS_CHAP2);
        assertThat(v2).isNotNull();
        assertThat(v2.v2()).isTrue();
        assertThat(v2.ident()).isEqualTo(7);
        assertThat(v2.challenge()).hasSize(8).isEqualTo(v2.challengeHash());
        assertThat(v2.ntResponse()).hasSize(24);

        MsChapAuthenticator.Request v1 = MsChapAuthenticator.request(
                packet(StoreAccessHandlerTest.msChap1("User", "clientPass", true)), AccessRequests.METHOD_MS_CHAP);
        assertThat(v1).isNotNull();
        assertThat(v1.v2()).isFalse();
        assertThat(v1.ident()).isEqualTo(3);
        assertThat(v1.challengeHash()).isNull();
    }

    @Test
    void malformedRequestsAreNotParsed() {
        assertThat(MsChapAuthenticator.request(
                        packet(StoreAccessHandlerTest.msChap1("User", "clientPass", false)),
                        AccessRequests.METHOD_MS_CHAP))
                .as("v1 with the LAN Manager response only")
                .isNull();
        byte[] response = new byte[50];
        response[1] = 1;
        assertThat(MsChapAuthenticator.request(
                        packet(StoreAccessHandlerTest.msChapRequest("User", new byte[16], 1, response)),
                        AccessRequests.METHOD_MS_CHAP))
                .as("v1 with a 16-byte challenge")
                .isNull();
        assertThat(MsChapAuthenticator.request(
                        packet(StoreAccessHandlerTest.msChapRequest("User", new byte[16], 25, new byte[49])),
                        AccessRequests.METHOD_MS_CHAP2))
                .as("a response of 49 bytes")
                .isNull();
        assertThat(MsChapAuthenticator.request(
                        packet(StoreAccessHandlerTest.msChap2("User", "clientPass")), AccessRequests.METHOD_MS_CHAP))
                .as("v2 attributes, but asked for v1: no MS-CHAP-Response")
                .isNull();
    }

    @Test
    void onlyTheTwoMsChapMethodsAreMsChap() {
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_MS_CHAP)).isTrue();
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_MS_CHAP2)).isTrue();
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_PAP)).isFalse();
        assertThat(MsChapAuthenticator.isMsChap(AccessRequests.METHOD_EAP)).isFalse();
    }

    @Test
    void theErrorNamesTheFailureAndForV2TheChallenge() {
        String v2 = error(StoreAccessHandlerTest.msChap2("User", "x"), AccessRequests.METHOD_MS_CHAP2);
        assertThat(v2).startsWith("\u0007E=691 R=0 C=").endsWith(" V=3");
        assertThat(error(StoreAccessHandlerTest.msChap1("User", "x", true), AccessRequests.METHOD_MS_CHAP))
                .isEqualTo("\u0003E=691 R=0");
    }

    /** The MS-CHAP-Error value written in reply to {@code request}, as text. */
    private static String error(byte[] request, int method) {
        AccessContext context = new AccessContext();
        context.reset(
                new UnsafeBuffer(request),
                0,
                request.length,
                AuthAgentTest.registry(io.radiusward.gateway.NasClient.MessageAuthenticatorPolicy.OFF)
                        .clients()
                        .iterator()
                        .next());
        MsChapAuthenticator.writeError(context, method);
        byte[] reply = new byte[context.replyAttributesLength()];
        context.replyBuffer().getBytes(RadiusPacket.HEADER_LENGTH, reply);
        assertThat(reply[0] & 0xFF).as("Vendor-Specific").isEqualTo(26);
        assertThat(reply[6] & 0xFF).as("MS-CHAP-Error").isEqualTo(2);
        return new String(reply, 8, reply.length - 8, StandardCharsets.US_ASCII);
    }
}
