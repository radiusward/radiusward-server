/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.SECRET;
import static io.radiusward.radius.codec.Packets.wrap;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class AccountingResponsesTest {

    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();
    private final AccountingResponses responses = new AccountingResponses(authenticator);

    @Test
    void responseEchoesIdentifierAndProxyStateOnly() {
        RadiusPacket request = wrap(Packets.accountingRequest(77, false));
        UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        int length = responses.encode(request, out, 0, SECRET, false);

        RadiusPacket response = wrap(Arrays.copyOf(out.byteArray(), length));
        assertThat(response.isValid()).isTrue();
        assertThat(response.code()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
        assertThat(response.identifier()).isEqualTo(77);

        List<String> attributes = new ArrayList<>();
        AttributeCursor cursor = new AttributeCursor().wrap(response);
        while (cursor.next()) {
            attributes.add(cursor.type() + "="
                    + AttributeValues.string(cursor.buffer(), cursor.valueOffset(), cursor.valueLength()));
        }
        assertThat(attributes).containsExactly("33=proxy-1", "33=proxy-2");
        assertThat(authenticator.verifyResponse(response, request.buffer(), request.authenticatorOffset(), SECRET))
                .isTrue();
    }

    @Test
    void responseAtOffset() {
        RadiusPacket request = wrap(Packets.accountingRequest(1, false));
        UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH + 100]);
        int length = responses.encode(request, out, 100, SECRET, false);
        RadiusPacket response = new RadiusPacket();
        assertThat(response.wrap(out, 100, length)).isEqualTo(DecodeStatus.OK);
        assertThat(authenticator.verifyResponse(response, request.buffer(), request.authenticatorOffset(), SECRET))
                .isTrue();
    }
}
