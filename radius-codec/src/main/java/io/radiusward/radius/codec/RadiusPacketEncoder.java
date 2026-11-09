/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static java.nio.ByteOrder.BIG_ENDIAN;

import java.nio.charset.StandardCharsets;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;

/**
 * Writes a RADIUS packet into a {@link MutableDirectBuffer}. Reusable and allocation-free except for
 * the {@code String} convenience method.
 *
 * <pre>{@code
 * int length = encoder.wrap(buffer, 0)
 *         .header(RadiusCode.ACCOUNTING_RESPONSE, request.identifier())
 *         .attribute(33, proxyState, offset, len)
 *         .finish();
 * }</pre>
 *
 * <p>The authenticator is left zeroed (or as set by {@link #authenticator}); sign the packet with
 * {@link RadiusAuthenticator} after {@link #finish()}. Exceeding 4096 bytes or the buffer capacity
 * throws {@link IllegalStateException}: that is a programming error, not bad input.
 */
public final class RadiusPacketEncoder {

    /** Largest value of a single attribute (255 minus the two byte header). */
    public static final int MAX_VALUE_LENGTH = 253;

    private MutableDirectBuffer buffer;
    private int offset;
    private int position;
    private int limit;

    public RadiusPacketEncoder wrap(MutableDirectBuffer buffer, int offset) {
        this.buffer = buffer;
        this.offset = offset;
        this.position = offset + RadiusPacket.HEADER_LENGTH;
        this.limit = offset + Math.min(RadiusPacket.MAX_LENGTH, buffer.capacity() - offset);
        return this;
    }

    /** Writes code and identifier and zeroes the authenticator. */
    public RadiusPacketEncoder header(int code, int identifier) {
        if (limit - offset < RadiusPacket.HEADER_LENGTH) {
            throw new IllegalStateException("buffer too small for a RADIUS header");
        }
        buffer.putByte(offset + RadiusPacket.CODE_OFFSET, (byte) code);
        buffer.putByte(offset + RadiusPacket.IDENTIFIER_OFFSET, (byte) identifier);
        buffer.setMemory(offset + RadiusPacket.AUTHENTICATOR_OFFSET, RadiusPacket.AUTHENTICATOR_LENGTH, (byte) 0);
        return this;
    }

    /** Copies 16 authenticator bytes from {@code source}. */
    public RadiusPacketEncoder authenticator(DirectBuffer source, int sourceOffset) {
        buffer.putBytes(
                offset + RadiusPacket.AUTHENTICATOR_OFFSET, source, sourceOffset, RadiusPacket.AUTHENTICATOR_LENGTH);
        return this;
    }

    public RadiusPacketEncoder authenticator(byte[] authenticator) {
        if (authenticator.length != RadiusPacket.AUTHENTICATOR_LENGTH) {
            throw new IllegalArgumentException("authenticator must be 16 bytes");
        }
        buffer.putBytes(offset + RadiusPacket.AUTHENTICATOR_OFFSET, authenticator);
        return this;
    }

    public RadiusPacketEncoder attribute(int type, DirectBuffer value, int valueOffset, int valueLength) {
        beginAttribute(type, valueLength);
        buffer.putBytes(position, value, valueOffset, valueLength);
        position += valueLength;
        return this;
    }

    public RadiusPacketEncoder attribute(int type, byte[] value) {
        beginAttribute(type, value.length);
        buffer.putBytes(position, value);
        position += value.length;
        return this;
    }

    /** UTF-8 text attribute. Allocates; for tooling. */
    public RadiusPacketEncoder attribute(int type, String value) {
        return attribute(type, value.getBytes(StandardCharsets.UTF_8));
    }

    public RadiusPacketEncoder uint32(int type, long value) {
        beginAttribute(type, 4);
        buffer.putInt(position, (int) value, BIG_ENDIAN);
        position += 4;
        return this;
    }

    public RadiusPacketEncoder uint64(int type, long value) {
        beginAttribute(type, 8);
        buffer.putLong(position, value, BIG_ENDIAN);
        position += 8;
        return this;
    }

    /** IPv4 address given as an unsigned 32 bit value. */
    public RadiusPacketEncoder ipv4(int type, long address) {
        return uint32(type, address);
    }

    /** Copies an attribute, header included, e.g. Proxy-State from a request into its response. */
    public RadiusPacketEncoder rawAttribute(DirectBuffer source, int attributeOffset) {
        int length = source.getByte(attributeOffset + 1) & 0xFF;
        ensure(length);
        buffer.putBytes(position, source, attributeOffset, length);
        position += length;
        return this;
    }

    /** Copies already encoded attributes (type, length, value …), e.g. a reply template. */
    public RadiusPacketEncoder rawAttributes(DirectBuffer source, int sourceOffset, int length) {
        ensure(length);
        buffer.putBytes(position, source, sourceOffset, length);
        position += length;
        return this;
    }

    /** RFC 2865 Vendor-Specific attribute holding one standard-format (1,1) sub-attribute. */
    public RadiusPacketEncoder vendorAttribute(
            int vendorId, int vendorType, DirectBuffer value, int valueOffset, int valueLength) {
        beginVendorAttribute(vendorId, vendorType, valueLength);
        buffer.putBytes(position, value, valueOffset, valueLength);
        position += valueLength;
        return this;
    }

    public RadiusPacketEncoder vendorAttribute(int vendorId, int vendorType, byte[] value) {
        beginVendorAttribute(vendorId, vendorType, value.length);
        buffer.putBytes(position, value);
        position += value.length;
        return this;
    }

    /** UTF-8 text vendor attribute. Allocates; for tooling. */
    public RadiusPacketEncoder vendorAttribute(int vendorId, int vendorType, String value) {
        return vendorAttribute(vendorId, vendorType, value.getBytes(StandardCharsets.UTF_8));
    }

    public RadiusPacketEncoder vendorUint32(int vendorId, int vendorType, long value) {
        beginVendorAttribute(vendorId, vendorType, 4);
        buffer.putInt(position, (int) value, BIG_ENDIAN);
        position += 4;
        return this;
    }

    /**
     * Appends a zeroed Message-Authenticator; {@link RadiusAuthenticator} fills it in when signing.
     *
     * @return absolute offset of the attribute header
     */
    public int messageAuthenticator() {
        int at = position;
        beginAttribute(RadiusPacket.MESSAGE_AUTHENTICATOR, 16);
        buffer.setMemory(position, 16, (byte) 0);
        position += 16;
        return at;
    }

    /** Writes the Length field and returns the packet length. */
    public int finish() {
        int length = position - offset;
        buffer.putShort(offset + RadiusPacket.LENGTH_OFFSET, (short) length, BIG_ENDIAN);
        return length;
    }

    /** Bytes written so far, header included. */
    public int length() {
        return position - offset;
    }

    private void beginAttribute(int type, int valueLength) {
        if (valueLength > MAX_VALUE_LENGTH) {
            throw new IllegalArgumentException("attribute " + type + " value too long: " + valueLength);
        }
        ensure(2 + valueLength);
        buffer.putByte(position, (byte) type);
        buffer.putByte(position + 1, (byte) (2 + valueLength));
        position += 2;
    }

    private void beginVendorAttribute(int vendorId, int vendorType, int valueLength) {
        int subLength = 2 + valueLength;
        if (6 + subLength > 255) {
            throw new IllegalArgumentException("vendor attribute " + vendorId + ":" + vendorType + " too long");
        }
        ensure(6 + subLength);
        buffer.putByte(position, (byte) AttributeCursor.VENDOR_SPECIFIC);
        buffer.putByte(position + 1, (byte) (6 + subLength));
        buffer.putInt(position + 2, vendorId, BIG_ENDIAN);
        buffer.putByte(position + 6, (byte) vendorType);
        buffer.putByte(position + 7, (byte) subLength);
        position += 8;
    }

    private void ensure(int bytes) {
        if (position + bytes > limit) {
            throw new IllegalStateException("RADIUS packet would exceed " + (limit - offset) + " bytes");
        }
    }
}
