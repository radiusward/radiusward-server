/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.SECRET;
import static io.radiusward.radius.codec.Packets.wrap;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.aaa4j.radius.core.attribute.Attribute;
import org.aaa4j.radius.core.attribute.IntegerData;
import org.aaa4j.radius.core.attribute.Ipv4AddrData;
import org.aaa4j.radius.core.attribute.RawAttribute;
import org.aaa4j.radius.core.attribute.StandardAttribute;
import org.aaa4j.radius.core.attribute.StringData;
import org.aaa4j.radius.core.attribute.TextData;
import org.aaa4j.radius.core.packet.Packet;
import org.aaa4j.radius.core.packet.PacketCodec;
import org.aaa4j.radius.dictionaries.freeradius.FreeRadiusDictionary;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** Cross-checks our codec against aaa4j-radius, an independent Apache-2.0 implementation. */
class Aaa4jDifferentialTest {

    private static final PacketCodec AAA4J = new PacketCodec(new FreeRadiusDictionary());

    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();

    private static byte[] aaa4jAccountingRequest(List<Attribute<?>> attributes) throws Exception {
        return AAA4J.encodeRequest(new Packet(RadiusCode.ACCOUNTING_REQUEST, attributes), SECRET, new byte[16]);
    }

    /** A standard-format VSA built by hand, so aaa4j copies it verbatim. */
    private static RawAttribute vsa(int vendorId, int type, String value) {
        byte[] text = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] data = new byte[4 + 2 + text.length];
        java.nio.ByteBuffer.wrap(data)
                .putInt(vendorId)
                .put((byte) type)
                .put((byte) (2 + text.length))
                .put(text);
        return new RawAttribute(26, data);
    }

    @Test
    void aaa4jAccountingRequestVerifiesAndDecodes() throws Exception {
        byte[] bytes = aaa4jAccountingRequest(List.of(
                new StandardAttribute<>(40, new IntegerData(3)),
                new StandardAttribute<>(44, new TextData("sess-42")),
                new StandardAttribute<>(4, new Ipv4AddrData((Inet4Address) InetAddress.getByName("10.1.2.3"))),
                new StandardAttribute<>(42, new IntegerData(123456)),
                vsa(9, 1, "audit-session-id=abc"),
                vsa(14988, 8, "10M/20M")));

        RadiusPacket packet = wrap(bytes);
        assertThat(packet.status()).isEqualTo(DecodeStatus.OK);
        assertThat(authenticator.verifyAccountingRequest(packet, SECRET)).isTrue();

        List<String> seen = new ArrayList<>();
        AttributeCursor cursor = new AttributeCursor().wrap(packet);
        while (cursor.next()) {
            seen.add(cursor.vendorId() + ":" + cursor.type());
            if (cursor.vendorId() == 0 && cursor.type() == 40) {
                assertThat(AttributeValues.uint32(cursor.buffer(), cursor.valueOffset(), cursor.valueLength()))
                        .isEqualTo(3);
            }
            if (cursor.vendorId() == 0 && cursor.type() == 4) {
                assertThat(AttributeValues.ipv4String(
                                AttributeValues.ipv4(cursor.buffer(), cursor.valueOffset(), cursor.valueLength())))
                        .isEqualTo("10.1.2.3");
            }
            if (cursor.vendorId() == 14988) {
                assertThat(AttributeValues.string(cursor.buffer(), cursor.valueOffset(), cursor.valueLength()))
                        .isEqualTo("10M/20M");
            }
        }
        assertThat(seen).containsExactly("0:40", "0:44", "0:4", "0:42", "9:1", "14988:8");
    }

    @Test
    void aaa4jMessageAuthenticatorVerifies() throws Exception {
        byte[] bytes = aaa4jAccountingRequest(List.of(
                new StandardAttribute<>(40, new IntegerData(1)),
                new StandardAttribute<>(80, new StringData(new byte[16]))));
        RadiusPacket packet = wrap(bytes);
        assertThat(packet.hasMessageAuthenticator()).isTrue();
        assertThat(authenticator.verifyRequestMessageAuthenticator(packet, SECRET))
                .isTrue();
        assertThat(authenticator.verifyAccountingRequest(packet, SECRET)).isTrue();
    }

    @Test
    void ourAccountingRequestDecodesInAaa4j() throws Exception {
        Packet decoded = AAA4J.decodeRequest(Packets.accountingRequest(11, false), SECRET);
        assertThat(decoded.getCode()).isEqualTo(RadiusCode.ACCOUNTING_REQUEST);
        assertThat(decoded.getAttributes()).hasSize(7);
    }

    @Test
    void ourAccountingResponseVerifiesInAaa4j() throws Exception {
        byte[] request = Packets.accountingRequest(12, false);
        RadiusPacket requestView = wrap(request);
        for (boolean withMessageAuthenticator : new boolean[] {false, true}) {
            UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
            int length = new AccountingResponses(authenticator)
                    .encode(requestView, out, 0, SECRET, withMessageAuthenticator);
            byte[] response = Arrays.copyOf(out.byteArray(), length);
            Packet decoded = AAA4J.decodeResponse(response, SECRET, Arrays.copyOfRange(request, 4, 20));
            assertThat(decoded.getCode()).isEqualTo(RadiusCode.ACCOUNTING_RESPONSE);
        }
    }

    // ---- Access-Request (Phase 5) ----------------------------------------------------------------

    private static final byte[] ACCESS_AUTHENTICATOR = Packets.hex("00112233445566778899aabbccddeeff");

    /** aaa4j's own User-Password filter (RFC 2865 §5.2) as the independent implementation. */
    private static org.aaa4j.radius.core.attribute.CodecContext context() {
        return new org.aaa4j.radius.core.attribute.CodecContext(
                new FreeRadiusDictionary(), SECRET, ACCESS_AUTHENTICATOR, new java.security.SecureRandom()::nextBytes);
    }

    @Property(tries = 200)
    void userPasswordEncryptedByAaa4jDecryptsHere(
            @ForAll @net.jqwik.api.constraints.StringLength(min = 1, max = 128) @net.jqwik.api.constraints.AlphaChars
                    String password) {
        byte[] cipher = org.aaa4j.radius.core.attribute.UserPasswordDataFilter.INSTANCE.encode(
                context(), password.getBytes(StandardCharsets.UTF_8));
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[256]);
        int length = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_REQUEST, 3)
                .authenticator(ACCESS_AUTHENTICATOR)
                .attribute(2, cipher)
                .finish();
        UnsafeBuffer out = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests()
                .decryptUserPassword(wrap(Arrays.copyOf(buffer.byteArray(), length)), SECRET, out, 0);
        assertThat(out.getStringWithoutLengthUtf8(0, n)).isEqualTo(password);
    }

    @Test
    void userPasswordEncryptedHereDecryptsInAaa4j() {
        byte[] plain = "a password longer than one block".getBytes(StandardCharsets.UTF_8);
        UnsafeBuffer cipher = new UnsafeBuffer(new byte[128]);
        int n = new AccessRequests()
                .encryptUserPassword(
                        new UnsafeBuffer(plain),
                        0,
                        plain.length,
                        new UnsafeBuffer(ACCESS_AUTHENTICATOR),
                        0,
                        SECRET,
                        cipher,
                        0);
        byte[] decrypted = org.aaa4j.radius.core.attribute.UserPasswordDataFilter.INSTANCE.decode(
                context(), Arrays.copyOf(cipher.byteArray(), n));
        assertThat(new String(decrypted, StandardCharsets.UTF_8).replace("\0", ""))
                .isEqualTo(new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    void ourAccessRepliesVerifyInAaa4j() throws Exception {
        byte[] request = AAA4J.encodeRequest(
                new Packet(
                        RadiusCode.ACCESS_REQUEST,
                        List.of(
                                new StandardAttribute<>(1, new StringData("nemo".getBytes(StandardCharsets.UTF_8))),
                                new StandardAttribute<>(
                                        2, new StringData("arctangent".getBytes(StandardCharsets.UTF_8))),
                                new StandardAttribute<>(
                                        33, new StringData("state-1".getBytes(StandardCharsets.UTF_8))))),
                SECRET,
                ACCESS_AUTHENTICATOR);
        RadiusPacket view = wrap(request);
        UnsafeBuffer attributes = new UnsafeBuffer(new byte[] {27, 6, 0, 0, 14, 16}); // Session-Timeout 3600
        for (int code : new int[] {RadiusCode.ACCESS_ACCEPT, RadiusCode.ACCESS_REJECT, RadiusCode.ACCESS_CHALLENGE}) {
            UnsafeBuffer out = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
            int length = new AccessResponses(authenticator)
                    .encode(view, code, attributes, 0, attributes.capacity(), out, 0, SECRET);
            Packet decoded = AAA4J.decodeResponse(
                    Arrays.copyOf(out.byteArray(), length), SECRET, Arrays.copyOfRange(request, 4, 20));
            assertThat(decoded.getCode()).isEqualTo(code);
            assertThat(decoded.getAttributes())
                    .extracting(a -> a.getType().head())
                    .contains(80, 27, 33);
        }
    }

    record Raw(int type, byte[] value) {}

    @Provide
    Arbitrary<List<Raw>> rawAttributes() {
        // standard types whose aaa4j encoding is a plain copy (no encryption, tags or VSA handling)
        Arbitrary<Integer> types = Arbitraries.integers()
                .between(1, 255)
                .filter(t -> t != 2 && t != 26 && t != 80 && t != 69 && !(t >= 64 && t <= 91) && t < 241);
        Arbitrary<byte[]> values =
                Arbitraries.bytes().array(byte[].class).ofMinSize(0).ofMaxSize(40);
        return Combinators.combine(types, values).as(Raw::new).list().ofMaxSize(30);
    }

    @Property(tries = 300)
    void randomRawAttributesMatchAaa4j(@ForAll("rawAttributes") List<Raw> attributes) throws Exception {
        List<Attribute<?>> aaa4jAttributes = new ArrayList<>();
        for (Raw raw : attributes) {
            aaa4jAttributes.add(new RawAttribute(raw.type(), raw.value()));
        }
        byte[] bytes = aaa4jAccountingRequest(aaa4jAttributes);
        RadiusPacket packet = wrap(bytes);
        assertThat(packet.status()).isEqualTo(DecodeStatus.OK);
        assertThat(authenticator.verifyAccountingRequest(packet, SECRET)).isTrue();

        AttributeCursor cursor = new AttributeCursor().wrap(packet);
        for (Raw raw : attributes) {
            assertThat(cursor.next()).isTrue();
            assertThat(cursor.type()).isEqualTo(raw.type());
            byte[] value = new byte[cursor.valueLength()];
            cursor.buffer().getBytes(cursor.valueOffset(), value);
            assertThat(value).isEqualTo(raw.value());
        }
        assertThat(cursor.next()).isFalse();
    }
}
