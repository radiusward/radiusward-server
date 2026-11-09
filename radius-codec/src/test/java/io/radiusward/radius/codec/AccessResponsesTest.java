/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.AccessRequestsTest.attribute;
import static io.radiusward.radius.codec.AccessRequestsTest.request;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class AccessResponsesTest {

    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccessResponses responses = new AccessResponses(authenticator);
    private final UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);

    /** Reply attributes as a policy would prepare them: Session-Timeout 3600, Reply-Message "hi". */
    static UnsafeBuffer template() {
        UnsafeBuffer t = new UnsafeBuffer(new byte[64]);
        int length = new RadiusPacketEncoder()
                        .wrap(t, 0)
                        .header(0, 0)
                        .uint32(27, 3600)
                        .attribute(18, "hi".getBytes())
                        .finish()
                - RadiusPacket.HEADER_LENGTH;
        return new UnsafeBuffer(
                Arrays.copyOfRange(t.byteArray(), RadiusPacket.HEADER_LENGTH, RadiusPacket.HEADER_LENGTH + length));
    }

    @Test
    void acceptStartsWithMessageAuthenticatorAndCopiesProxyStatesInOrder() {
        byte[] request = request(
                attribute(1, "nemo".getBytes()),
                attribute(33, "proxy-a".getBytes()),
                attribute(2, new byte[16]),
                attribute(33, "proxy-b".getBytes()));
        RadiusPacket req = Packets.wrap(request);
        UnsafeBuffer attributes = template();
        int length = responses.encode(
                req, RadiusCode.ACCESS_ACCEPT, attributes, 0, attributes.capacity(), out, 0, Packets.SECRET);

        RadiusPacket reply = Packets.wrap(Arrays.copyOf(out.byteArray(), length));
        assertThat(reply.code()).isEqualTo(RadiusCode.ACCESS_ACCEPT);
        assertThat(reply.identifier()).isEqualTo(7);
        assertThat(reply.buffer().getByte(RadiusPacket.HEADER_LENGTH))
                .as("Message-Authenticator first (BlastRADIUS)")
                .isEqualTo((byte) RadiusPacket.MESSAGE_AUTHENTICATOR);
        assertThat(authenticator.verifyResponse(reply, req.buffer(), req.authenticatorOffset(), Packets.SECRET))
                .isTrue();
        assertThat(authenticator.verifyResponseMessageAuthenticator(
                        reply, req.buffer(), req.authenticatorOffset(), Packets.SECRET))
                .isTrue();
        // then the template, then both Proxy-States in request order
        int at = RadiusPacket.HEADER_LENGTH + 18;
        assertThat(Arrays.copyOfRange(reply.buffer().byteArray(), at, at + attributes.capacity()))
                .isEqualTo(attributes.byteArray());
        String tail =
                new String(reply.buffer().byteArray(), at + attributes.capacity(), length - at - attributes.capacity());
        assertThat(tail.indexOf("proxy-a")).isNotNegative().isLessThan(tail.indexOf("proxy-b"));
        assertThat(authenticator.verifyResponse(reply, req.buffer(), req.authenticatorOffset(), "other".getBytes()))
                .isFalse();
    }

    @Test
    void rejectAndChallengeWithoutAttributes() {
        RadiusPacket req = Packets.wrap(request(attribute(1, "nemo".getBytes())));
        for (int code : new int[] {RadiusCode.ACCESS_REJECT, RadiusCode.ACCESS_CHALLENGE}) {
            int length = responses.encode(req, code, out, 0, 0, out, 0, Packets.SECRET);
            assertThat(length).as("header + Message-Authenticator").isEqualTo(20 + 18);
            RadiusPacket reply = Packets.wrap(Arrays.copyOf(out.byteArray(), length));
            assertThat(reply.code()).isEqualTo(code);
            assertThat(authenticator.verifyResponseMessageAuthenticator(
                            reply, req.buffer(), req.authenticatorOffset(), Packets.SECRET))
                    .isTrue();
        }
        assertThatThrownBy(
                        () -> responses.encode(req, RadiusCode.ACCOUNTING_RESPONSE, out, 0, 0, out, 0, Packets.SECRET))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
