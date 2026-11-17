/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** The proxy's rewriting of a request for the home server and of its answer for the NAS (ADR 0037). */
class ProxyCodecTest {

    private static final byte[] NAS_SECRET = "nas-secret".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] HOME_SECRET = "home-secret".getBytes(StandardCharsets.US_ASCII);
    private static final int SLOT = 1;

    private final byte[] nasAuthenticator = filled(16, 5);
    private final UnsafeBuffer packets = new UnsafeBuffer(new byte[2 * RadiusPacket.MAX_LENGTH]);
    private final UnsafeBuffer ourAuthenticators = new UnsafeBuffer(new byte[32]);
    private final UnsafeBuffer nasAuthenticators = new UnsafeBuffer(new byte[32]);
    private final UnsafeBuffer reply = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final ProxyCodec codec = new ProxyCodec(packets, ourAuthenticators, nasAuthenticators, reply);
    private final ProxyConfig.Realm partner =
            new ProxyConfig.Realm("partner", "partner".getBytes(StandardCharsets.US_ASCII), "pool", true, false);

    private static byte[] filled(int length, int value) {
        byte[] b = new byte[length];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static RadiusPacket wrap(UnsafeBuffer buffer, int offset, int length) {
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(buffer, offset, length);
        return packet;
    }

    /** A NAS's Access-Request; {@code password} encrypted with the NAS secret, or CHAP without a challenge. */
    private RadiusPacket nasRequest(String user, String password, boolean chap) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 9)
                .authenticator(nasAuthenticator)
                .attribute(1, user);
        if (chap) {
            enc.attribute(3, filled(17, 1));
        } else {
            byte[] plain = password.getBytes(StandardCharsets.US_ASCII);
            UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
            int n = new AccessRequests()
                    .encryptUserPassword(
                            new UnsafeBuffer(plain),
                            0,
                            plain.length,
                            new UnsafeBuffer(nasAuthenticator),
                            0,
                            NAS_SECRET,
                            cipher,
                            0);
            enc.attribute(2, Arrays.copyOf(cipher.byteArray(), n));
        }
        enc.attribute(31, "aa-bb-cc");
        int length = enc.finish();
        return wrap(buffer, 0, length);
    }

    private RadiusPacket sent(int length) {
        return wrap(packets, SLOT * RadiusPacket.MAX_LENGTH, length);
    }

    @Test
    void theRequestIsEncryptedStrippedAndSignedForTheHomeServer() {
        int length = codec.request(
                nasRequest("alice@partner", "secret-pass", false), partner, NAS_SECRET, HOME_SECRET, SLOT, 3, 42);
        assertThat(length).isPositive();
        RadiusPacket sent = sent(length);
        assertThat(sent.code()).isEqualTo(RadiusCode.ACCESS_REQUEST);
        assertThat(sent.identifier()).isEqualTo(42);
        assertThat(sent.string(1)).as("the realm strips the User-Name").isEqualTo("alice");
        assertThat(sent.string(31)).as("other attributes as they were").isEqualTo("aa-bb-cc");
        UnsafeBuffer password = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests().decryptUserPassword(sent, HOME_SECRET, password, 0);
        assertThat(new String(password.byteArray(), 0, n, StandardCharsets.US_ASCII))
                .as("re-encrypted with the home server's secret")
                .isEqualTo("secret-pass");
        assertThat(new RadiusAuthenticator().verifyRequestMessageAuthenticator(sent, HOME_SECRET))
                .isTrue();
        assertThat(sent.valueLength(sent.findAttribute(33)))
                .as("our Proxy-State")
                .isEqualTo(8);
        byte[] ours = new byte[16];
        ourAuthenticators.getBytes(SLOT * 16, ours);
        byte[] onTheWire = new byte[16];
        sent.buffer().getBytes(sent.authenticatorOffset(), onTheWire);
        assertThat(ours).as("kept to check the answer").isEqualTo(onTheWire);
    }

    @Test
    void chapKeepsItsChallengeWhenItWasTheRequestAuthenticator() {
        int length = codec.request(nasRequest("bob", null, true), partner, NAS_SECRET, HOME_SECRET, SLOT, 0, 7);
        RadiusPacket sent = sent(length);
        assertThat(sent.octets(60))
                .as("CHAP-Challenge: the NAS's Request Authenticator")
                .isEqualTo(nasAuthenticator);
    }

    @Test
    void theAnswerLosesOurProxyStateAndGetsTheKeysAndSignatureOfTheNas() {
        int length =
                codec.request(nasRequest("alice@partner", "pw", false), partner, NAS_SECRET, HOME_SECRET, SLOT, 3, 42);
        RadiusPacket sent = sent(length);
        nasAuthenticators.putBytes(SLOT * 16, nasAuthenticator);
        byte[] ours = new byte[16];
        ourAuthenticators.getBytes(SLOT * 16, ours);

        byte[] send = filled(16, 1);
        byte[] receive = filled(16, 2);
        byte[] sendValue = MsChap.encryptKey(send, HOME_SECRET, ours, new byte[] {(byte) 0x80, 2});
        byte[] receiveValue = MsChap.encryptKey(receive, HOME_SECRET, ours, new byte[] {(byte) 0x80, 3});
        ByteBuffer vsa = ByteBuffer.allocate(4 + 2 + sendValue.length + 2 + receiveValue.length); // both in one VSA
        vsa.putInt(Microsoft.VENDOR_ID);
        vsa.put((byte) Microsoft.MPPE_SEND_KEY)
                .put((byte) (2 + sendValue.length))
                .put(sendValue);
        vsa.put((byte) Microsoft.MPPE_RECV_KEY)
                .put((byte) (2 + receiveValue.length))
                .put(receiveValue);
        UnsafeBuffer home = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        int homeLength = new RadiusPacketEncoder()
                .wrap(home, 0)
                .header(RadiusCode.ACCESS_ACCEPT, 42)
                .authenticator(new byte[16])
                .attribute(18, "welcome")
                .attribute(33, sent.octets(33))
                .attribute(26, vsa.array())
                .finish();

        int out = codec.answer(
                wrap(home, 0, homeLength), RadiusCode.ACCESS_ACCEPT, 9, partner, HOME_SECRET, NAS_SECRET, SLOT);
        assertThat(out).isPositive();
        RadiusPacket answer = wrap(reply, 0, out);
        assertThat(answer.code()).isEqualTo(RadiusCode.ACCESS_ACCEPT);
        assertThat(answer.identifier()).as("the NAS's identifier").isEqualTo(9);
        assertThat(answer.findAttribute(33)).as("our Proxy-State stays with us").isNegative();
        assertThat(answer.string(18)).isEqualTo("welcome");
        RadiusAuthenticator signer = new RadiusAuthenticator();
        assertThat(signer.verifyResponse(answer, new UnsafeBuffer(nasAuthenticator), 0, NAS_SECRET))
                .isTrue();
        assertThat(signer.verifyResponseMessageAuthenticator(answer, new UnsafeBuffer(nasAuthenticator), 0, NAS_SECRET))
                .isTrue();
        AttributeCursor cursor = new AttributeCursor().wrap(answer);
        assertThat(cursor.find(Microsoft.VENDOR_ID, Microsoft.MPPE_SEND_KEY)).isTrue();
        assertThat(InnerProxy.decryptKey(value(cursor), nasAuthenticator, NAS_SECRET))
                .as("re-encrypted for the NAS")
                .isEqualTo(send);
        assertThat(cursor.find(Microsoft.VENDOR_ID, Microsoft.MPPE_RECV_KEY)).isTrue();
        assertThat(InnerProxy.decryptKey(value(cursor), nasAuthenticator, NAS_SECRET))
                .isEqualTo(receive);
    }

    @Test
    void anAnswerWithAnotherProxyStateKeepsIt() {
        int length =
                codec.request(nasRequest("alice@partner", "pw", false), partner, NAS_SECRET, HOME_SECRET, SLOT, 3, 42);
        nasAuthenticators.putBytes(SLOT * 16, nasAuthenticator);
        byte[] foreign = sent(length).octets(33);
        foreign[0] ^= 1; // another gateway's token
        UnsafeBuffer home = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        int homeLength = new RadiusPacketEncoder()
                .wrap(home, 0)
                .header(RadiusCode.ACCESS_REJECT, 42)
                .authenticator(new byte[16])
                .attribute(33, foreign)
                .finish();
        int out = codec.answer(
                wrap(home, 0, homeLength), RadiusCode.ACCESS_REJECT, 9, partner, HOME_SECRET, NAS_SECRET, SLOT);
        assertThat(wrap(reply, 0, out).octets(33)).as("not ours: the NAS's own").isEqualTo(foreign);
    }

    private static byte[] value(AttributeCursor cursor) {
        byte[] v = new byte[cursor.valueLength()];
        cursor.buffer().getBytes(cursor.valueOffset(), v);
        return v;
    }
}
