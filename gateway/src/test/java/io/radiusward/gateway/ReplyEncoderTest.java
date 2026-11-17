/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.agrona.collections.IntHashSet;
import org.agrona.collections.Object2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;

class ReplyEncoderTest {

    private static final int CISCO = 9;

    private final ReplyEncoder encoder = new ReplyEncoder(
            StoreAccessHandlerTest.DICTIONARY,
            new OnceLogger(LogManager.getLogger(ReplyEncoderTest.class)),
            Set.of("nas"));
    private final Object2ObjectHashMap<AttributeItem, ReplyEncoder.Encoded> cache = new Object2ObjectHashMap<>();

    private static AttributeItem item(String attribute, String op, String value) {
        return new AttributeItem(attribute, op, value);
    }

    /** Encodes {@code reply} into an Access-Accept and returns it. */
    private RadiusPacket encode(List<AttributeItem> reply, IntHashSet vendors, int cacheMax) {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[4096]);
        RadiusPacketEncoder out = new RadiusPacketEncoder()
                .wrap(buffer, 0)
                .header(RadiusCode.ACCESS_ACCEPT, 1)
                .authenticator(new byte[16]);
        encoder.encode(cache, reply, out, vendors, "nas", cacheMax);
        int length = out.finish();
        RadiusPacket packet = new RadiusPacket();
        packet.wrap(buffer, 0, length);
        return packet;
    }

    @Test
    void groupItemsAddToTheUsersOrReplaceNothing() {
        List<AttributeItem> reply = new ArrayList<>(List.of(item("Session-Timeout", ":=", "600")));
        ReplyEncoder.merge(
                reply,
                List.of(
                        item("Session-Timeout", "=", "3600"),
                        item("Reply-Message", "+=", "hello"),
                        item("Idle-Timeout", "=", "60")));
        assertThat(reply)
                .containsExactly(
                        item("Session-Timeout", ":=", "600"),
                        item("Reply-Message", "+=", "hello"),
                        item("Idle-Timeout", "=", "60"));
        ReplyEncoder.merge(reply, List.of(item("Reply-Message", "+=", "again")));
        assertThat(reply).filteredOn(i -> i.attribute().equals("Reply-Message")).hasSize(2);
    }

    @Test
    void vendorAttributesGoOnlyToNasEntriesOfThatVendor() {
        List<AttributeItem> reply = List.of(item("Idle-Timeout", ":=", "60"), item("Cisco-AVPair", "+=", "a=b"));
        RadiusPacket all = encode(reply, null, 100);
        assertThat(all.findAttribute(28)).isPositive();
        assertThat(all.findAttribute(26)).as("no filter: every vendor").isPositive();

        IntHashSet juniperOnly = new IntHashSet();
        juniperOnly.add(2636);
        RadiusPacket filtered = encode(reply, juniperOnly, 100);
        assertThat(filtered.findAttribute(28)).as("standard attributes always").isPositive();
        assertThat(filtered.findAttribute(26)).isNegative();
        assertThat(encoder.filtered("nas")).isEqualTo(1);

        IntHashSet cisco = new IntHashSet();
        cisco.add(CISCO);
        assertThat(encode(reply, cisco, 100).findAttribute(26)).isPositive();
        assertThat(encoder.filtered("nas")).isEqualTo(1);
    }

    @Test
    void itemsThatCannotBeSentAreSkipped() {
        RadiusPacket packet = encode(
                List.of(
                        item("No-Such-Attribute", ":=", "1"),
                        item("Idle-Timeout", ":=", "not a number"),
                        item("Reply-Message", ":=", "x".repeat(300)),
                        item("Idle-Timeout", ":=", "60")),
                null,
                100);
        assertThat(packet.findAttribute(18)).as("too long").isNegative();
        int at = packet.findAttribute(28);
        assertThat(packet.buffer().getInt(at + 2, java.nio.ByteOrder.BIG_ENDIAN))
                .isEqualTo(60);
    }

    @Test
    void itemsAreEncodedOnceWithinTheBoundButPerRequestValuesNever() {
        encode(List.of(item("Idle-Timeout", ":=", "60"), item("Framed-IP-Address", ":=", "10.0.0.1")), null, 2);
        assertThat(cache).containsOnlyKeys(item("Idle-Timeout", ":=", "60"));
        encode(List.of(item("Idle-Timeout", ":=", "61"), item("Idle-Timeout", ":=", "62")), null, 2);
        assertThat(cache).as("full: cleared, then refilled").containsOnlyKeys(item("Idle-Timeout", ":=", "62"));
    }

    @Test
    void withoutADictionaryNothingIsSent() {
        ReplyEncoder bare =
                new ReplyEncoder(null, new OnceLogger(LogManager.getLogger(ReplyEncoderTest.class)), Set.of());
        RadiusPacketEncoder out = new RadiusPacketEncoder()
                .wrap(new UnsafeBuffer(new byte[4096]), 0)
                .header(RadiusCode.ACCESS_ACCEPT, 1)
                .authenticator(new byte[16]);
        bare.encode(cache, List.of(item("Idle-Timeout", ":=", "60")), out, null, "nas", 100);
        assertThat(out.finish()).isEqualTo(RadiusPacket.HEADER_LENGTH);
    }

    @Test
    void aReloadKeepsTheCountsOfKeptEntries() {
        IntHashSet none = new IntHashSet();
        encode(List.of(item("Cisco-AVPair", "+=", "a=b")), none, 100);
        encoder.reload(Set.of("nas", "other"));
        assertThat(encoder.filtered("nas")).isEqualTo(1);
        assertThat(encoder.filtered("other")).isZero();
        encoder.reload(Set.of("other"));
        assertThat(encoder.filtered("nas")).as("no longer filtered").isZero();
        encode(List.of(item("Cisco-AVPair", "+=", "a=b")), none, 100);
        assertThat(encoder.filtered("nas"))
                .as("not counted while the entry has no filter")
                .isZero();
    }
}
