/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.constraints.Size;
import org.agrona.concurrent.UnsafeBuffer;

/** The decoder must never throw or read outside the packet, whatever arrives on the socket. */
class CodecFuzzTest {

    private static final VendorFormats MIXED_FORMATS = vendorId -> switch (vendorId & 3) {
        case 0 -> VendorFormats.STANDARD;
        case 1 -> VendorFormats.pack(2, 1, false);
        case 2 -> VendorFormats.pack(4, 0, false);
        default -> VendorFormats.pack(1, 1, true);
    };

    private final RadiusAuthenticator authenticator = new RadiusAuthenticator();

    @Property(tries = 3000)
    void randomBytes(@ForAll @Size(max = 600) byte[] bytes) {
        exercise(bytes, bytes.length);
    }

    @Provide
    Arbitrary<byte[]> plausiblePackets() {
        // a valid header followed by random attribute bytes: reaches the attribute walk far more often
        return Arbitraries.bytes()
                .array(byte[].class)
                .ofMinSize(0)
                .ofMaxSize(300)
                .map(attributes -> {
                    byte[] packet = new byte[20 + attributes.length];
                    packet[0] = RadiusCode.ACCOUNTING_REQUEST;
                    packet[2] = (byte) (packet.length >> 8);
                    packet[3] = (byte) packet.length;
                    System.arraycopy(attributes, 0, packet, 20, attributes.length);
                    return packet;
                });
    }

    @Property(tries = 3000)
    void randomAttributeRegions(@ForAll("plausiblePackets") byte[] bytes) {
        exercise(bytes, bytes.length);
    }

    @Property(tries = 2000)
    void mutatedValidPackets(
            @ForAll @IntRange(min = 0, max = 400) int position,
            @ForAll byte xor,
            @ForAll @IntRange(min = 0, max = 400) int truncate) {
        byte[] valid = Packets.accountingRequest(1, true);
        byte[] mutated = valid.clone();
        mutated[position % mutated.length] ^= xor;
        exercise(mutated, mutated.length);
        exercise(Arrays.copyOf(valid, Math.min(truncate, valid.length)), Math.min(truncate, valid.length));
    }

    private void exercise(byte[] bytes, int receivedLength) {
        // place the datagram inside a larger buffer with guard bytes on both sides
        int pad = 16;
        byte[] backing = new byte[bytes.length + 2 * pad];
        System.arraycopy(bytes, 0, backing, pad, bytes.length);
        UnsafeBuffer buffer = new UnsafeBuffer(backing);

        RadiusPacket packet = new RadiusPacket();
        DecodeStatus status = packet.wrap(buffer, pad, receivedLength);
        if (status != DecodeStatus.OK) {
            return;
        }
        int start = pad;
        int end = pad + packet.length();
        assertThat(packet.length()).isBetween(20, Math.min(receivedLength, RadiusPacket.MAX_LENGTH));

        // Access-Request credential handling: statuses, never exceptions or reads outside the packet
        AccessRequests access = new AccessRequests();
        int method = access.method(packet);
        assertThat(method).isBetween(AccessRequests.METHOD_AMBIGUOUS, AccessRequests.METHOD_EAP);
        UnsafeBuffer password = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
        int decrypted = access.decryptUserPassword(packet, Packets.SECRET, password, 0);
        assertThat(decrypted).isBetween(AccessRequests.MALFORMED, AccessRequests.MAX_PASSWORD);
        assertThat(access.verifyChap(packet, password, 0, Math.max(0, decrypted)))
                .isBetween(AccessRequests.MALFORMED, AccessRequests.CHAP_MATCH);

        AttributeCursor cursor = new AttributeCursor(MIXED_FORMATS).wrap(packet);
        int count = 0;
        while (cursor.next()) {
            assertThat(cursor.valueLength()).isNotNegative();
            assertThat(cursor.valueOffset()).isGreaterThanOrEqualTo(start + 20);
            assertThat(cursor.valueOffset() + cursor.valueLength()).isLessThanOrEqualTo(end);
            assertThat(cursor.attributeOffset() + cursor.attributeLength()).isLessThanOrEqualTo(end);
            assertThat(++count).isLessThan(4096);
        }
        packet.findAttribute(40);
        authenticator.verifyAccountingRequest(packet, Packets.SECRET);
        authenticator.verifyRequestMessageAuthenticator(packet, Packets.SECRET);
    }
}
