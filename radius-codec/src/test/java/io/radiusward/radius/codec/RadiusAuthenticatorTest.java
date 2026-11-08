/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.SECRET;
import static io.radiusward.radius.codec.Packets.hex;
import static io.radiusward.radius.codec.Packets.wrap;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RadiusAuthenticatorTest {

    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();

    /** RFC 2865 §7.1: Access-Accept answering the example Access-Request, secret "xyzzy5461". */
    @Test
    void rfc2865ResponseAuthenticator() {
        byte[] request = hex(RadiusPacketTest.RFC2865_ACCESS_REQUEST);
        byte[] expected = hex(
                "02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf 9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00 0e 06 c0 a8 01 03");
        byte[] secret = "xyzzy5461".getBytes(StandardCharsets.US_ASCII);

        UnsafeBuffer out = new UnsafeBuffer(new byte[64]);
        int length = new RadiusPacketEncoder()
                .wrap(out, 0)
                .header(RadiusCode.ACCESS_ACCEPT, 0)
                .uint32(6, 1) // Service-Type = Login-User
                .uint32(15, 0) // Login-Service = Telnet
                .ipv4(14, 0xC0A80103L) // Login-IP-Host = 192.168.1.3
                .finish();
        authenticator.signResponse(out, 0, length, -1, new UnsafeBuffer(request), 4, secret);

        byte[] actual = Arrays.copyOf(out.byteArray(), length);
        assertThat(Packets.hex(actual)).isEqualTo(Packets.hex(expected));
        assertThat(authenticator.verifyResponse(wrap(actual), new UnsafeBuffer(request), 4, secret))
                .isTrue();
        assertThat(authenticator.verifyResponse(wrap(actual), new UnsafeBuffer(request), 4, SECRET))
                .isFalse();
    }

    @Test
    void accountingRequestRoundTrip() {
        byte[] packet = Packets.accountingRequest(42, false);
        assertThat(authenticator.verifyAccountingRequest(wrap(packet), SECRET)).isTrue();
        assertThat(authenticator.verifyAccountingRequest(wrap(packet), "wrong".getBytes(StandardCharsets.US_ASCII)))
                .isFalse();
    }

    @Test
    void tamperedAccountingRequestFails() {
        byte[] packet = Packets.accountingRequest(42, false);
        for (int i = 0; i < packet.length; i++) {
            if (i == 2 || i == 3) {
                continue; // length changes make the packet invalid rather than unauthentic
            }
            byte[] copy = packet.clone();
            copy[i] ^= 0x01;
            RadiusPacket view = wrap(copy);
            if (view.isValid()) {
                assertThat(authenticator.verifyAccountingRequest(view, SECRET))
                        .as("flipped byte %d", i)
                        .isFalse();
            }
        }
    }

    @Test
    void accountingRequestMessageAuthenticator() {
        byte[] packet = Packets.accountingRequest(9, true);
        RadiusPacket view = wrap(packet);
        assertThat(authenticator.verifyAccountingRequest(view, SECRET)).isTrue();
        assertThat(authenticator.verifyRequestMessageAuthenticator(view, SECRET))
                .isTrue();

        byte[] tampered = packet.clone();
        tampered[view.messageAuthenticatorOffset() + 5] ^= 0x10;
        assertThat(authenticator.verifyRequestMessageAuthenticator(wrap(tampered), SECRET))
                .isFalse();
        assertThat(authenticator.verifyRequestMessageAuthenticator(wrap(Packets.accountingRequest(9, false)), SECRET))
                .isFalse();
    }

    @Test
    void accessRequestMessageAuthenticatorUsesOwnAuthenticator() throws Exception {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[128]);
        RadiusPacketEncoder encoder = new RadiusPacketEncoder().wrap(buffer, 0);
        byte[] nonce = hex("00112233445566778899aabbccddeeff");
        encoder.header(RadiusCode.ACCESS_REQUEST, 3).authenticator(nonce).attribute(1, "bob");
        int ma = encoder.messageAuthenticator();
        int length = encoder.finish();
        // compute the expected HMAC with the JDK over the packet with a zeroed MA value
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(SECRET, "HmacMD5"));
        mac.update(buffer.byteArray(), 0, length);
        buffer.putBytes(ma + 2, mac.doFinal());

        byte[] packet = Arrays.copyOf(buffer.byteArray(), length);
        assertThat(authenticator.verifyRequestMessageAuthenticator(wrap(packet), SECRET))
                .isTrue();
    }

    @Test
    void responseMessageAuthenticator() {
        byte[] request = Packets.accountingRequest(5, false);
        RadiusPacket requestView = wrap(request);
        UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
        int length = new AccountingResponses(authenticator).encode(requestView, out, 0, SECRET, true);
        RadiusPacket response = wrap(Arrays.copyOf(out.byteArray(), length));

        assertThat(authenticator.verifyResponse(
                        response, requestView.buffer(), requestView.authenticatorOffset(), SECRET))
                .isTrue();
        assertThat(authenticator.verifyResponseMessageAuthenticator(
                        response, requestView.buffer(), requestView.authenticatorOffset(), SECRET))
                .isTrue();
        assertThat(authenticator.verifyResponseMessageAuthenticator(
                        wrap(request), requestView.buffer(), requestView.authenticatorOffset(), SECRET))
                .isFalse();
    }

    @Test
    void rfc2104HmacVectors() {
        assertHmac(
                repeat((byte) 0x0b, 16),
                "Hi There".getBytes(StandardCharsets.US_ASCII),
                "9294727a3638bb1c13f48ef8158bfc9d");
        assertHmac(
                "Jefe".getBytes(StandardCharsets.US_ASCII),
                "what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII),
                "750c783e6ab0b503eaa86e310a5db738");
        assertHmac(repeat((byte) 0xaa, 16), repeat((byte) 0xdd, 50), "56be34521d144c88dbb8c733f0e8b3f6");
        // RFC 2202 test case 6: key longer than the block size is hashed first
        assertHmac(
                repeat((byte) 0xaa, 80),
                "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(StandardCharsets.US_ASCII),
                "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 63, 64, 65, 200})
    void hmacMatchesJdkForAnyKeyLength(int keyLength) throws Exception {
        byte[] key = new byte[keyLength];
        for (int i = 0; i < keyLength; i++) {
            key[i] = (byte) (i * 7 + 3);
        }
        byte[] message = Packets.accountingRequest(1, false);
        byte[] ours = new byte[16];
        authenticator.hmacMd5(message, message.length, key, ours);
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(keyLength == 0 ? new byte[1] : key, "HmacMD5"));
        if (keyLength == 0) {
            // JDK rejects empty keys; an all-zero one-byte key is equivalent after zero padding
            mac.init(new SecretKeySpec(new byte[] {0}, "HmacMD5"));
        }
        mac.update(message);
        assertThat(Packets.hex(ours)).isEqualTo(Packets.hex(mac.doFinal()));
    }

    private void assertHmac(byte[] key, byte[] message, String expected) {
        byte[] out = new byte[16];
        authenticator.hmacMd5(message, message.length, key, out);
        assertThat(Packets.hex(out)).isEqualTo(expected);
    }

    private static byte[] repeat(byte value, int count) {
        byte[] bytes = new byte[count];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
