/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static java.nio.ByteOrder.BIG_ENDIAN;

import org.agrona.DirectBuffer;

/**
 * Reusable, allocation-free view over a received RADIUS packet.
 *
 * <pre>
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Code      |  Identifier   |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Authenticator (16)                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Attributes ...
 * </pre>
 *
 * <p>{@link #wrap(DirectBuffer, int, int)} validates the header and the attribute framing once;
 * after {@link DecodeStatus#OK} every accessor and {@link AttributeCursor} walk stays in bounds.
 * Not thread-safe: one instance per owning thread.
 */
public final class RadiusPacket {

    public static final int CODE_OFFSET = 0;
    public static final int IDENTIFIER_OFFSET = 1;
    public static final int LENGTH_OFFSET = 2;
    public static final int AUTHENTICATOR_OFFSET = 4;
    public static final int AUTHENTICATOR_LENGTH = 16;
    public static final int HEADER_LENGTH = 20;
    public static final int MAX_LENGTH = 4096;

    /** RFC 2869 Message-Authenticator. */
    public static final int MESSAGE_AUTHENTICATOR = 80;

    public static final int MESSAGE_AUTHENTICATOR_LENGTH = 18;

    private DirectBuffer buffer;
    private int offset;
    private int length;
    private int messageAuthenticatorOffset = -1;
    private DecodeStatus status = DecodeStatus.TOO_SHORT;

    /**
     * Points this view at a received datagram and validates it.
     *
     * @param buffer buffer holding the datagram
     * @param offset start of the datagram
     * @param receivedLength number of bytes received; bytes beyond the Length field are ignored
     */
    public DecodeStatus wrap(DirectBuffer buffer, int offset, int receivedLength) {
        this.buffer = buffer;
        this.offset = offset;
        this.length = 0;
        this.messageAuthenticatorOffset = -1;
        status = validate(receivedLength);
        return status;
    }

    private DecodeStatus validate(int receivedLength) {
        if (receivedLength < HEADER_LENGTH) {
            return DecodeStatus.TOO_SHORT;
        }
        int declared = buffer.getShort(offset + LENGTH_OFFSET, BIG_ENDIAN) & 0xFFFF;
        if (declared < HEADER_LENGTH || declared > MAX_LENGTH) {
            return DecodeStatus.INVALID_LENGTH;
        }
        if (declared > receivedLength) {
            return DecodeStatus.TRUNCATED;
        }
        int position = offset + HEADER_LENGTH;
        int end = offset + declared;
        while (position < end) {
            if (end - position < 2) {
                return DecodeStatus.MALFORMED_ATTRIBUTE;
            }
            int type = buffer.getByte(position) & 0xFF;
            int attributeLength = buffer.getByte(position + 1) & 0xFF;
            if (attributeLength < 2 || position + attributeLength > end) {
                return DecodeStatus.MALFORMED_ATTRIBUTE;
            }
            if (type == MESSAGE_AUTHENTICATOR) {
                if (attributeLength != MESSAGE_AUTHENTICATOR_LENGTH) {
                    return DecodeStatus.MALFORMED_MESSAGE_AUTHENTICATOR;
                }
                if (messageAuthenticatorOffset < 0) {
                    messageAuthenticatorOffset = position;
                }
            }
            position += attributeLength;
        }
        this.length = declared;
        return DecodeStatus.OK;
    }

    /** Status of the last {@link #wrap}. */
    public DecodeStatus status() {
        return status;
    }

    public boolean isValid() {
        return status == DecodeStatus.OK;
    }

    public DirectBuffer buffer() {
        return buffer;
    }

    /** Offset of the packet's first byte in {@link #buffer()}. */
    public int offset() {
        return offset;
    }

    public int code() {
        return buffer.getByte(offset + CODE_OFFSET) & 0xFF;
    }

    public int identifier() {
        return buffer.getByte(offset + IDENTIFIER_OFFSET) & 0xFF;
    }

    /** Value of the Length field; only meaningful when valid. */
    public int length() {
        return length;
    }

    /** Absolute offset of the 16 byte authenticator in {@link #buffer()}. */
    public int authenticatorOffset() {
        return offset + AUTHENTICATOR_OFFSET;
    }

    /** Absolute offset of the first attribute. */
    public int attributesOffset() {
        return offset + HEADER_LENGTH;
    }

    /** Absolute offset one past the last attribute byte. */
    public int attributesEnd() {
        return offset + length;
    }

    /** Absolute offset of the first Message-Authenticator attribute header, or {@code -1}. */
    public int messageAuthenticatorOffset() {
        return messageAuthenticatorOffset;
    }

    public boolean hasMessageAuthenticator() {
        return messageAuthenticatorOffset >= 0;
    }

    /**
     * Absolute offset of the first top-level attribute of the given type (its header), or {@code -1}.
     * Allocation-free.
     */
    public int findAttribute(int type) {
        int position = attributesOffset();
        int end = attributesEnd();
        while (position < end) {
            if ((buffer.getByte(position) & 0xFF) == type) {
                return position;
            }
            position += buffer.getByte(position + 1) & 0xFF;
        }
        return -1;
    }
}
