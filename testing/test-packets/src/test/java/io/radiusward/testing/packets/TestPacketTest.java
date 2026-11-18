/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing.packets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class TestPacketTest {

    private static final byte[] SECRET = "testing123".getBytes(StandardCharsets.US_ASCII);

    private static RadiusPacket wrap(byte[] bytes) {
        RadiusPacket p = new RadiusPacket();
        p.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
        assertThat(p.isValid()).as("a well-formed packet").isTrue();
        return p;
    }

    @Test
    void accountingRequestsAreSignedWithTheSecret() {
        byte[] bytes = TestPacket.accountingRequest(300)
                .uint32(40, 1)
                .attribute(44, "s-1")
                .messageAuthenticator()
                .secret(SECRET)
                .build();
        RadiusPacket p = wrap(bytes);
        assertThat(p.code()).isEqualTo(RadiusCode.ACCOUNTING_REQUEST);
        assertThat(p.identifier()).as("identifiers wrap at 256").isEqualTo(300 & 0xFF);
        assertThat(p.string(44)).isEqualTo("s-1");
        RadiusAuthenticator authenticator = new RadiusAuthenticator();
        assertThat(authenticator.verifyAccountingRequest(p, SECRET)).isTrue();
        assertThat(authenticator.verifyRequestMessageAuthenticator(p, SECRET)).isTrue();
        assertThat(authenticator.verifyAccountingRequest(p, "other".getBytes(StandardCharsets.US_ASCII)))
                .isFalse();
    }

    @Test
    void coaAndDisconnectRequestsAreSignedLikeAccounting() {
        for (int code : new int[] {RadiusCode.COA_REQUEST, RadiusCode.DISCONNECT_REQUEST}) {
            RadiusPacket p = wrap(TestPacket.request(code, 1)
                    .attribute(1, "alice")
                    .secret("testing123")
                    .build());
            assertThat(p.code()).isEqualTo(code);
            assertThat(new RadiusAuthenticator().verifyAccountingRequest(p, SECRET))
                    .isTrue();
        }
    }

    @Test
    void accessRequestsHideThePasswordAndCarryAValidMessageAuthenticator() {
        byte[] fixed = new byte[16];
        Arrays.fill(fixed, (byte) 7);
        RadiusPacket p = wrap(TestPacket.accessRequest(9)
                .authenticator(fixed)
                .messageAuthenticator()
                .attribute(1, "alice")
                .password("a password longer than sixteen octets")
                .secret(SECRET)
                .build());
        assertThat(p.messageAuthenticatorOffset())
                .as("written where it was added: first")
                .isEqualTo(RadiusPacket.HEADER_LENGTH);
        assertThat(new RadiusAuthenticator().verifyRequestMessageAuthenticator(p, SECRET))
                .isTrue();
        byte[] authenticator = new byte[16];
        p.buffer().getBytes(p.authenticatorOffset(), authenticator);
        assertThat(authenticator).isEqualTo(fixed);
        UnsafeBuffer plain = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests().decryptUserPassword(p, SECRET, plain, 0);
        assertThat(plain.getStringWithoutLengthUtf8(0, n)).isEqualTo("a password longer than sixteen octets");
    }

    @Test
    void anAccessRequestWithoutSignatureNeedsNoSecretAndGetsARandomAuthenticator() {
        byte[] a = TestPacket.accessRequest(1).attribute(1, "bob").build();
        byte[] b = TestPacket.accessRequest(1).attribute(1, "bob").build();
        assertThat(wrap(a).hasMessageAuthenticator()).isFalse();
        assertThat(Arrays.copyOfRange(a, 4, 20)).isNotEqualTo(Arrays.copyOfRange(b, 4, 20));
    }

    @Test
    void statusServerIsSignedByItsMessageAuthenticator() {
        RadiusPacket p = wrap(
                TestPacket.statusServer(4).messageAuthenticator().secret(SECRET).build());
        assertThat(p.code()).isEqualTo(RadiusCode.STATUS_SERVER);
        assertThat(new RadiusAuthenticator().verifyRequestMessageAuthenticator(p, SECRET))
                .isTrue();
    }

    @Test
    void repliesAreSignedAgainstTheirRequest() {
        byte[] request = TestPacket.accessRequest(77).attribute(1, "alice").build();
        RadiusPacket reply = wrap(TestPacket.reply(RadiusCode.ACCESS_ACCEPT, request)
                .attribute(18, "welcome")
                .messageAuthenticator()
                .secret(SECRET)
                .build());
        assertThat(reply.identifier()).as("the request's").isEqualTo(77);
        assertThat(reply.string(18)).isEqualTo("welcome");
        assertThat(new RadiusAuthenticator().verifyResponse(reply, new UnsafeBuffer(request), 4, SECRET, true))
                .isTrue();
    }

    @Test
    void valuesOfEveryKindAreEncoded() {
        RadiusPacket p = wrap(TestPacket.accessRequest(1)
                .uint32(27, 600)
                .ipv4(8, "10.9.0.1")
                .vendor(311, 11, new byte[] {1, 2})
                .vendor(9, 1, "a=b")
                .raw(new byte[] {33, 4, 'x', 'y'})
                .build());
        assertThat(p.octets(27)).containsExactly(0, 0, 2, 0x58);
        assertThat(p.octets(8)).containsExactly(10, 9, 0, 1);
        assertThat(p.octets(33)).containsExactly('x', 'y');
        int vsa = p.findAttribute(26);
        assertThat(p.buffer().getInt(vsa + 2, java.nio.ByteOrder.BIG_ENDIAN)).isEqualTo(311);
    }

    @Test
    void mistakesAreReportedWhenTheyAreMade() {
        assertThatThrownBy(() -> TestPacket.accountingRequest(1).build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("secret");
        assertThatThrownBy(() -> TestPacket.accessRequest(1).password("p").build())
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> TestPacket.accountingRequest(1).authenticator(new byte[16]))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> TestPacket.reply(2, new byte[20]).authenticator(new byte[16]))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> TestPacket.accessRequest(1).raw(new byte[] {1, 5, 'a'}))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TestPacket.accessRequest(1).ipv4(4, "10.0.1"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
