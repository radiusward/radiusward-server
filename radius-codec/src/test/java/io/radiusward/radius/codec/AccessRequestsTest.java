/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.hex;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AccessRequestsTest {

    static final byte[] RFC_SECRET = "xyzzy5461".getBytes(StandardCharsets.US_ASCII);
    static final byte[] AUTHENTICATOR = hex("0f403f9473978057bd83d5cb98f4227a");

    private final AccessRequests requests = new AccessRequests();
    private final UnsafeBuffer out = new UnsafeBuffer(new byte[256]);

    private String decrypt(byte[] packet, byte[] secret) {
        int n = requests.decryptUserPassword(Packets.wrap(packet), secret, out, 0);
        return n < 0 ? Integer.toString(n) : out.getStringWithoutLengthUtf8(0, n);
    }

    /** An Access-Request with the given attributes after the header, authenticator {@link #AUTHENTICATOR}. */
    static byte[] request(byte[]... attributes) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 7)
                .authenticator(AUTHENTICATOR);
        for (byte[] attribute : attributes) {
            encoder.attribute(attribute[0] & 0xFF, Arrays.copyOfRange(attribute, 1, attribute.length));
        }
        return Arrays.copyOf(buffer.byteArray(), encoder.finish());
    }

    static byte[] attribute(int type, byte[] value) {
        byte[] a = new byte[value.length + 1];
        a[0] = (byte) type;
        System.arraycopy(value, 0, a, 1, value.length);
        return a;
    }

    private byte[] encrypted(String password, byte[] secret) {
        byte[] plain = password.getBytes(StandardCharsets.UTF_8);
        UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
        int n = requests.encryptUserPassword(
                new UnsafeBuffer(plain), 0, plain.length, new UnsafeBuffer(AUTHENTICATOR), 0, secret, cipher, 0);
        return Arrays.copyOf(cipher.byteArray(), n);
    }

    // ---- PAP ---------------------------------------------------------------------------------

    /** RFC 2865 §7.1: user "nemo", password "arctangent", secret "xyzzy5461". */
    @Test
    void rfc2865UserPassword() {
        byte[] packet = hex(RadiusPacketTest.RFC2865_ACCESS_REQUEST);
        assertThat(requests.method(Packets.wrap(packet))).isEqualTo(AccessRequests.METHOD_PAP);
        assertThat(decrypt(packet, RFC_SECRET)).isEqualTo("arctangent");
        assertThat(decrypt(packet, "wrong".getBytes(StandardCharsets.US_ASCII))).isNotEqualTo("arctangent");
        assertThat(encrypted("arctangent", RFC_SECRET))
                .as("the RFC's ciphertext")
                .isEqualTo(hex("0dbe708d93d413ce3196e43f782a0aee"));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 15, 16, 17, 31, 32, 33, 100, 128})
    void multiBlockPasswordsRoundTrip(int length) {
        String password = "p".repeat(length - 1) + "Z";
        byte[] packet = request(attribute(AccessRequests.USER_PASSWORD, encrypted(password, Packets.SECRET)));
        assertThat(decrypt(packet, Packets.SECRET)).isEqualTo(password);
    }

    @Test
    void malformedOrMissingUserPassword() {
        assertThat(decrypt(request(attribute(1, "nemo".getBytes())), Packets.SECRET))
                .isEqualTo("-1");
        assertThat(decrypt(request(attribute(2, new byte[15])), Packets.SECRET))
                .as("< 16")
                .isEqualTo("-2");
        assertThat(decrypt(request(attribute(2, new byte[17])), Packets.SECRET))
                .as("not × 16")
                .isEqualTo("-2");
        assertThat(decrypt(request(attribute(2, new byte[144])), Packets.SECRET))
                .as("> 128")
                .isEqualTo("-2");
        assertThat(decrypt(request(attribute(2, new byte[16]), attribute(2, new byte[16])), Packets.SECRET))
                .as("twice")
                .isEqualTo("-2");
        assertThat(requests.encryptUserPassword(
                        new UnsafeBuffer(new byte[129]),
                        0,
                        129,
                        new UnsafeBuffer(AUTHENTICATOR),
                        0,
                        Packets.SECRET,
                        out,
                        0))
                .isEqualTo(AccessRequests.MALFORMED);
    }

    // ---- CHAP --------------------------------------------------------------------------------

    /** Reference: MD5(Identifier + password + challenge), written independently with the JDK digest. */
    static byte[] chapPassword(int identifier, String password, byte[] challenge) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update((byte) identifier);
        md5.update(password.getBytes(StandardCharsets.UTF_8));
        md5.update(challenge);
        byte[] value = new byte[17];
        value[0] = (byte) identifier;
        System.arraycopy(md5.digest(), 0, value, 1, 16);
        return value;
    }

    private int chap(byte[] packet, String password) {
        byte[] p = password.getBytes(StandardCharsets.UTF_8);
        return requests.verifyChap(Packets.wrap(packet), new UnsafeBuffer(p), 0, p.length);
    }

    @Test
    void chapWithChapChallenge() throws Exception {
        byte[] challenge = hex("8e1d2c7f0a4b5c6d7e8f9011a2b3c4d5");
        byte[] packet = request(
                attribute(1, "nemo".getBytes()),
                attribute(AccessRequests.CHAP_PASSWORD, chapPassword(42, "arctangent", challenge)),
                attribute(AccessRequests.CHAP_CHALLENGE, challenge));
        assertThat(requests.method(Packets.wrap(packet))).isEqualTo(AccessRequests.METHOD_CHAP);
        assertThat(chap(packet, "arctangent")).isEqualTo(AccessRequests.CHAP_MATCH);
        assertThat(chap(packet, "arctangenT")).isEqualTo(AccessRequests.CHAP_MISMATCH);
        assertThat(chap(packet, "")).isEqualTo(AccessRequests.CHAP_MISMATCH);
    }

    @Test
    void chapWithoutChallengeUsesTheRequestAuthenticator() throws Exception {
        byte[] packet = request(attribute(AccessRequests.CHAP_PASSWORD, chapPassword(1, "secret pw", AUTHENTICATOR)));
        assertThat(chap(packet, "secret pw")).isEqualTo(AccessRequests.CHAP_MATCH);
        // a challenge of another length than 16 is allowed (RFC 1994)
        byte[] shortChallenge = hex("0102030405060708");
        byte[] other = request(
                attribute(AccessRequests.CHAP_PASSWORD, chapPassword(9, "secret pw", shortChallenge)),
                attribute(AccessRequests.CHAP_CHALLENGE, shortChallenge));
        assertThat(chap(other, "secret pw")).isEqualTo(AccessRequests.CHAP_MATCH);
    }

    @Test
    void malformedChap() throws Exception {
        assertThat(chap(request(attribute(1, "nemo".getBytes())), "x")).isEqualTo(AccessRequests.MISSING);
        assertThat(chap(request(attribute(AccessRequests.CHAP_PASSWORD, new byte[16])), "x"))
                .as("16 instead of 17 bytes")
                .isEqualTo(AccessRequests.MALFORMED);
        byte[] value = chapPassword(1, "x", AUTHENTICATOR);
        assertThat(chap(request(attribute(3, value), attribute(3, value)), "x")).isEqualTo(AccessRequests.MALFORMED);
        assertThat(chap(request(attribute(3, value), attribute(60, new byte[0])), "x"))
                .as("empty challenge")
                .isEqualTo(AccessRequests.MALFORMED);
    }

    // ---- method ------------------------------------------------------------------------------

    @Test
    void methodByAttributes() throws Exception {
        assertThat(requests.method(Packets.wrap(request(attribute(1, "u".getBytes())))))
                .isEqualTo(AccessRequests.METHOD_NONE);
        byte[] eap = request(attribute(1, "u".getBytes()), attribute(AccessRequests.EAP_MESSAGE, hex("0201000601")));
        assertThat(requests.method(Packets.wrap(eap))).isEqualTo(AccessRequests.METHOD_EAP);
        byte[] both = request(attribute(2, new byte[16]), attribute(3, chapPassword(1, "x", AUTHENTICATOR)));
        assertThat(requests.method(Packets.wrap(both))).isEqualTo(AccessRequests.METHOD_AMBIGUOUS);
        byte[] msChap2 = request(attribute(26, msVsa(AccessRequests.MS_CHAP2_RESPONSE, new byte[50])));
        assertThat(requests.method(Packets.wrap(msChap2))).isEqualTo(AccessRequests.METHOD_MS_CHAP2);
        byte[] msChap = request(attribute(26, msVsa(AccessRequests.MS_CHAP_RESPONSE, new byte[50])));
        assertThat(requests.method(Packets.wrap(msChap))).isEqualTo(AccessRequests.METHOD_MS_CHAP);
    }

    static byte[] msVsa(int vendorType, byte[] value) {
        byte[] v = new byte[6 + value.length];
        v[0] = 0;
        v[1] = 0;
        v[2] = 0x01;
        v[3] = 0x37; // 311
        v[4] = (byte) vendorType;
        v[5] = (byte) (value.length + 2);
        System.arraycopy(value, 0, v, 6, value.length);
        return v;
    }
}
