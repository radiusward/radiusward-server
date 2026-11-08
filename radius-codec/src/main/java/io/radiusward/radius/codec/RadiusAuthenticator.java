/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;

/**
 * Request/Response Authenticator (RFC 2865 §3, RFC 2866 §3) and Message-Authenticator (RFC 2869 §5.14,
 * RFC 3579 §3.2) computation.
 *
 * <p>One instance per thread: it reuses an MD5 digest and scratch buffers, so verifying and signing
 * allocate nothing. HMAC-MD5 is implemented over the same digest instead of {@code javax.crypto.Mac}
 * to avoid per-secret key objects. Comparisons are constant-time.
 *
 * <p>Rules for the authenticator field while computing Message-Authenticator, as FreeRADIUS does:
 * <ul>
 *   <li>Accounting-Request, CoA-Request, Disconnect-Request: sixteen zero bytes;
 *   <li>responses: the authenticator of the request being answered;
 *   <li>Access-Request, Status-Server: the packet's own random authenticator.
 * </ul>
 */
public final class RadiusAuthenticator {

    private static final int BLOCK = 64;
    private static final int DIGEST = 16;

    private final MessageDigest md5;
    private final byte[] scratch = new byte[RadiusPacket.MAX_LENGTH];
    private final byte[] digest = new byte[DIGEST];
    private final byte[] pad = new byte[BLOCK];
    private final byte[] hashedKey = new byte[DIGEST];

    public RadiusAuthenticator() {
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is required by the Java platform", e);
        }
    }

    // ---- requests ----------------------------------------------------------------------------

    /**
     * Verifies the Request Authenticator of an Accounting-Request (also CoA/Disconnect-Request):
     * {@code MD5(Code + Identifier + Length + 16 zero bytes + Attributes + Secret)}.
     */
    public boolean verifyAccountingRequest(RadiusPacket packet, byte[] secret) {
        int length = copyPacket(packet.buffer(), packet.offset(), packet.length());
        zero(scratch, RadiusPacket.AUTHENTICATOR_OFFSET, RadiusPacket.AUTHENTICATOR_LENGTH);
        md5(scratch, length, secret);
        return constantTimeEquals(digest, packet.buffer(), packet.authenticatorOffset());
    }

    /**
     * Verifies the Message-Authenticator of a request. For Accounting/CoA/Disconnect requests the
     * authenticator field is treated as zero, for Access-Request and Status-Server as sent.
     *
     * @return {@code false} if the packet has no Message-Authenticator or it does not match
     */
    public boolean verifyRequestMessageAuthenticator(RadiusPacket packet, byte[] secret) {
        if (!packet.hasMessageAuthenticator()) {
            return false;
        }
        int length = copyPacket(packet.buffer(), packet.offset(), packet.length());
        if (RadiusCode.hasComputedRequestAuthenticator(packet.code())) {
            zero(scratch, RadiusPacket.AUTHENTICATOR_OFFSET, RadiusPacket.AUTHENTICATOR_LENGTH);
        }
        return verifyHmac(packet, length, secret);
    }

    /**
     * Signs an Accounting-Request (or CoA/Disconnect-Request) in place: computes Message-Authenticator
     * at {@code messageAuthenticatorOffset} if that is not {@code -1}, then the Request Authenticator.
     */
    public void signAccountingRequest(
            MutableDirectBuffer buffer, int offset, int length, int messageAuthenticatorOffset, byte[] secret) {
        buffer.setMemory(offset + RadiusPacket.AUTHENTICATOR_OFFSET, RadiusPacket.AUTHENTICATOR_LENGTH, (byte) 0);
        if (messageAuthenticatorOffset >= 0) {
            writeHmac(buffer, offset, length, messageAuthenticatorOffset, secret);
        }
        int copied = copyPacket(buffer, offset, length);
        md5(scratch, copied, secret);
        buffer.putBytes(offset + RadiusPacket.AUTHENTICATOR_OFFSET, digest);
    }

    // ---- responses ---------------------------------------------------------------------------

    /**
     * Signs a response in place: {@code MD5(Code + Identifier + Length + Request Authenticator +
     * Attributes + Secret)}, computing Message-Authenticator first when
     * {@code messageAuthenticatorOffset} is not {@code -1}.
     *
     * @param requestAuthenticator buffer holding the request's 16 byte authenticator
     */
    public void signResponse(
            MutableDirectBuffer buffer,
            int offset,
            int length,
            int messageAuthenticatorOffset,
            DirectBuffer requestAuthenticator,
            int requestAuthenticatorOffset,
            byte[] secret) {
        buffer.putBytes(
                offset + RadiusPacket.AUTHENTICATOR_OFFSET,
                requestAuthenticator,
                requestAuthenticatorOffset,
                RadiusPacket.AUTHENTICATOR_LENGTH);
        if (messageAuthenticatorOffset >= 0) {
            writeHmac(buffer, offset, length, messageAuthenticatorOffset, secret);
        }
        int copied = copyPacket(buffer, offset, length);
        md5(scratch, copied, secret);
        buffer.putBytes(offset + RadiusPacket.AUTHENTICATOR_OFFSET, digest);
    }

    /** Verifies the Response Authenticator of a response to a request with the given authenticator. */
    public boolean verifyResponse(
            RadiusPacket response, DirectBuffer requestAuthenticator, int requestAuthenticatorOffset, byte[] secret) {
        int length = copyResponseWithRequestAuthenticator(response, requestAuthenticator, requestAuthenticatorOffset);
        md5(scratch, length, secret);
        return constantTimeEquals(digest, response.buffer(), response.authenticatorOffset());
    }

    /** Verifies the Message-Authenticator of a response; {@code false} if it has none. */
    public boolean verifyResponseMessageAuthenticator(
            RadiusPacket response, DirectBuffer requestAuthenticator, int requestAuthenticatorOffset, byte[] secret) {
        if (!response.hasMessageAuthenticator()) {
            return false;
        }
        int length = copyResponseWithRequestAuthenticator(response, requestAuthenticator, requestAuthenticatorOffset);
        return verifyHmac(response, length, secret);
    }

    // ---- internals ---------------------------------------------------------------------------

    private int copyResponseWithRequestAuthenticator(RadiusPacket response, DirectBuffer auth, int authOffset) {
        int length = copyPacket(response.buffer(), response.offset(), response.length());
        auth.getBytes(authOffset, scratch, RadiusPacket.AUTHENTICATOR_OFFSET, RadiusPacket.AUTHENTICATOR_LENGTH);
        return length;
    }

    /** HMAC over {@code scratch[0, length)} with the Message-Authenticator value zeroed, compared to the packet. */
    private boolean verifyHmac(RadiusPacket packet, int length, byte[] secret) {
        int valueOffset = packet.messageAuthenticatorOffset() - packet.offset() + 2;
        zero(scratch, valueOffset, DIGEST);
        hmacMd5(scratch, length, secret);
        return constantTimeEquals(digest, packet.buffer(), packet.messageAuthenticatorOffset() + 2);
    }

    /** Computes HMAC-MD5 over the packet as currently in {@code buffer} and writes it into the attribute. */
    private void writeHmac(MutableDirectBuffer buffer, int offset, int length, int attributeOffset, byte[] secret) {
        buffer.setMemory(attributeOffset + 2, DIGEST, (byte) 0);
        int copied = copyPacket(buffer, offset, length);
        hmacMd5(scratch, copied, secret);
        buffer.putBytes(attributeOffset + 2, digest);
    }

    private int copyPacket(DirectBuffer buffer, int offset, int length) {
        if (length < RadiusPacket.HEADER_LENGTH || length > RadiusPacket.MAX_LENGTH) {
            throw new IllegalArgumentException("invalid packet length " + length);
        }
        buffer.getBytes(offset, scratch, 0, length);
        return length;
    }

    private void md5(byte[] data, int length, byte[] secret) {
        md5.update(data, 0, length);
        md5.update(secret, 0, secret.length);
        finishDigest();
    }

    /** RFC 2104 HMAC with MD5: {@code MD5((K ^ opad) || MD5((K ^ ipad) || message))}. Result in {@link #digest}. */
    private void hmacMd5(byte[] message, int length, byte[] secret) {
        byte[] key = secret;
        int keyLength = secret.length;
        if (keyLength > BLOCK) {
            md5.update(secret, 0, secret.length);
            finishDigestInto(hashedKey);
            key = hashedKey;
            keyLength = DIGEST;
        }
        for (int i = 0; i < BLOCK; i++) {
            pad[i] = (byte) ((i < keyLength ? key[i] : 0) ^ 0x36);
        }
        md5.update(pad, 0, BLOCK);
        md5.update(message, 0, length);
        finishDigest();
        for (int i = 0; i < BLOCK; i++) {
            pad[i] = (byte) ((i < keyLength ? key[i] : 0) ^ 0x5c);
        }
        md5.update(pad, 0, BLOCK);
        md5.update(digest, 0, DIGEST);
        finishDigest();
    }

    /** HMAC-MD5 of {@code message[0, length)}; exposed for the RFC 2104 test vectors. */
    void hmacMd5(byte[] message, int length, byte[] key, byte[] out) {
        System.arraycopy(message, 0, scratch, 0, length);
        hmacMd5(scratch, length, key);
        System.arraycopy(digest, 0, out, 0, DIGEST);
    }

    private void finishDigest() {
        finishDigestInto(digest);
    }

    private void finishDigestInto(byte[] target) {
        try {
            md5.digest(target, 0, DIGEST);
        } catch (DigestException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void zero(byte[] array, int from, int count) {
        for (int i = from; i < from + count; i++) {
            array[i] = 0;
        }
    }

    private static boolean constantTimeEquals(byte[] expected, DirectBuffer actual, int actualOffset) {
        int diff = 0;
        for (int i = 0; i < DIGEST; i++) {
            diff |= expected[i] ^ actual.getByte(actualOffset + i);
        }
        return diff == 0;
    }
}
