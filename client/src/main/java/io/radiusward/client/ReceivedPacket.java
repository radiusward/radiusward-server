/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.radius.codec.AttributeCursor;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.agrona.concurrent.UnsafeBuffer;

/** A packet that arrived and verified: its code and attributes. */
public abstract sealed class ReceivedPacket permits Response, CoaRequest {

    private final byte[] bytes;
    private final RadiusPacket packet = new RadiusPacket();

    ReceivedPacket(byte[] bytes) {
        this.bytes = bytes;
        packet.wrap(new UnsafeBuffer(bytes), 0, bytes.length);
    }

    public int code() {
        return packet.code();
    }

    public int identifier() {
        return packet.identifier();
    }

    /** The first attribute {@code type} as text (UTF-8). */
    public Optional<String> string(int type) {
        return octets(type).map(v -> new String(v, StandardCharsets.UTF_8));
    }

    /** The value of the first attribute {@code type}. */
    public Optional<byte[]> octets(int type) {
        return Optional.ofNullable(packet.octets(type));
    }

    /** The first attribute {@code type} as an unsigned 32-bit number, such as Session-Timeout. */
    public OptionalLong integer(int type) {
        return octets(type)
                .filter(v -> v.length == 4)
                .map(v -> OptionalLong.of(
                        (v[0] & 0xFFL) << 24 | (v[1] & 0xFFL) << 16 | (v[2] & 0xFFL) << 8 | v[3] & 0xFFL))
                .orElse(OptionalLong.empty());
    }

    /** The values of every attribute {@code type}, in order (several Class or Reply-Message attributes). */
    public List<byte[]> all(int type) {
        return values(0, type);
    }

    /** The value of the first vendor attribute {@code vendorType} of {@code vendorId}, also inside packed VSAs. */
    public Optional<byte[]> vendor(int vendorId, int vendorType) {
        List<byte[]> values = values(vendorId, vendorType);
        return values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
    }

    private List<byte[]> values(int vendorId, int type) {
        List<byte[]> values = new ArrayList<>();
        AttributeCursor cursor = new AttributeCursor().wrap(packet);
        while (cursor.next()) {
            if (cursor.vendorId() == vendorId && cursor.type() == type) {
                byte[] v = new byte[cursor.valueLength()];
                cursor.buffer().getBytes(cursor.valueOffset(), v);
                values.add(v);
            }
        }
        return values;
    }

    /** The codec's view of the packet, for what the methods above do not cover. */
    public RadiusPacket packet() {
        return packet;
    }

    /** The packet as received. */
    public byte[] bytes() {
        return bytes.clone();
    }
}
