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
 * Credentials of an Access-Request: the authentication method it uses, User-Password decryption (RFC 2865 §5.2)
 * and CHAP verification (RFC 1994, RFC 2865 §5.3, §5.40).
 *
 * <p>One instance per thread: it reuses an MD5 digest and scratch buffers, so nothing is allocated per request, and
 * it zeroes its copies of plaintext after use. Malformed input gives a negative status, never an exception (the
 * request is then silently discarded, RFC 2865 §3).
 */
public final class AccessRequests {

    public static final int USER_PASSWORD = 2;
    public static final int CHAP_PASSWORD = 3;
    public static final int STATE = 24;
    public static final int CHAP_CHALLENGE = 60;
    public static final int EAP_MESSAGE = 79;
    /** Microsoft vendor attributes (RFC 2548) carrying MS-CHAP responses. */
    public static final int MICROSOFT = 311;

    public static final int MS_CHAP_RESPONSE = 1;
    public static final int MS_CHAP2_RESPONSE = 25;

    /** {@link #method} results. */
    public static final int METHOD_NONE = 0;

    public static final int METHOD_PAP = 1;
    public static final int METHOD_CHAP = 2;
    public static final int METHOD_MS_CHAP = 3;
    public static final int METHOD_MS_CHAP2 = 4;
    public static final int METHOD_EAP = 5;
    /** More than one method in one request (e.g. User-Password and CHAP-Password): RFC 2865 §5.2 forbids it. */
    public static final int METHOD_AMBIGUOUS = -1;

    /** Statuses of {@link #decryptUserPassword} and {@link #verifyChap}. */
    public static final int MISSING = -1;

    public static final int MALFORMED = -2;
    public static final int CHAP_MATCH = 1;
    public static final int CHAP_MISMATCH = 0;

    /** Longest User-Password value (RFC 2865 §5.2). */
    public static final int MAX_PASSWORD = 128;

    private static final int BLOCK = 16;
    private static final int CHAP_RESPONSE_LENGTH = 1 + BLOCK;

    private final MessageDigest md5;
    private final byte[] previous = new byte[BLOCK];
    private final byte[] keystream = new byte[BLOCK];
    private final byte[] plaintext = new byte[MAX_PASSWORD];
    private final byte[] value = new byte[RadiusPacketEncoder.MAX_VALUE_LENGTH];

    public AccessRequests() {
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 is required by the Java platform", e);
        }
    }

    /**
     * The authentication method of a request, by the attributes it carries (EAP wins over everything else, as an
     * EAP request may also carry a User-Name only).
     */
    public int method(RadiusPacket request) {
        DirectBuffer buffer = request.buffer();
        int found = METHOD_NONE;
        int count = 0;
        boolean eap = false;
        for (int position = request.attributesOffset(); position < request.attributesEnd(); ) {
            int type = buffer.getByte(position) & 0xFF;
            int length = buffer.getByte(position + 1) & 0xFF;
            int method = METHOD_NONE;
            if (type == EAP_MESSAGE) {
                eap = true;
            } else if (type == USER_PASSWORD) {
                method = METHOD_PAP;
            } else if (type == CHAP_PASSWORD) {
                method = METHOD_CHAP;
            } else if (type == 26
                    && length >= 8
                    && buffer.getInt(position + 2, java.nio.ByteOrder.BIG_ENDIAN) == MICROSOFT) {
                int vendorType = buffer.getByte(position + 6) & 0xFF;
                method = vendorType == MS_CHAP_RESPONSE
                        ? METHOD_MS_CHAP
                        : vendorType == MS_CHAP2_RESPONSE ? METHOD_MS_CHAP2 : METHOD_NONE;
            }
            if (method != METHOD_NONE && method != found) {
                found = method;
                count++;
            }
            position += length;
        }
        if (eap) {
            return METHOD_EAP;
        }
        return count > 1 ? METHOD_AMBIGUOUS : found;
    }

    /**
     * Decrypts the User-Password: {@code p(i) = c(i) XOR MD5(secret + c(i-1))}, {@code c(0)} = Request Authenticator;
     * trailing NUL padding is removed.
     *
     * @return the password length written to {@code out}, {@link #MISSING}, or {@link #MALFORMED} (length not a
     *     multiple of 16 between 16 and 128, or the attribute twice)
     */
    public int decryptUserPassword(RadiusPacket request, byte[] secret, MutableDirectBuffer out, int outOffset) {
        int attribute = single(request, USER_PASSWORD);
        if (attribute < 0) {
            return attribute;
        }
        DirectBuffer buffer = request.buffer();
        int length = (buffer.getByte(attribute + 1) & 0xFF) - 2;
        if (length < BLOCK || length > MAX_PASSWORD || length % BLOCK != 0) {
            return MALFORMED;
        }
        buffer.getBytes(request.authenticatorOffset(), previous, 0, BLOCK);
        for (int block = 0; block < length; block += BLOCK) {
            md5.update(secret);
            md5.update(previous, 0, BLOCK);
            digest(keystream);
            for (int i = 0; i < BLOCK; i++) {
                byte cipher = buffer.getByte(attribute + 2 + block + i);
                plaintext[block + i] = (byte) (cipher ^ keystream[i]);
                previous[i] = cipher;
            }
        }
        int n = length;
        while (n > 0 && plaintext[n - 1] == 0) {
            n--;
        }
        out.putBytes(outOffset, plaintext, 0, n);
        java.util.Arrays.fill(plaintext, 0, length, (byte) 0);
        java.util.Arrays.fill(keystream, (byte) 0);
        return n;
    }

    /**
     * Encrypts a password as User-Password for a request with the given authenticator (clients and tests).
     *
     * @return the encrypted length (a multiple of 16), or {@link #MALFORMED} if the password is longer than 128 bytes
     */
    public int encryptUserPassword(
            DirectBuffer password,
            int passwordOffset,
            int passwordLength,
            DirectBuffer authenticator,
            int authenticatorOffset,
            byte[] secret,
            MutableDirectBuffer out,
            int outOffset) {
        if (passwordLength > MAX_PASSWORD) {
            return MALFORMED;
        }
        int length = Math.max(BLOCK, (passwordLength + BLOCK - 1) / BLOCK * BLOCK);
        authenticator.getBytes(authenticatorOffset, previous, 0, BLOCK);
        for (int block = 0; block < length; block += BLOCK) {
            md5.update(secret);
            md5.update(previous, 0, BLOCK);
            digest(keystream);
            for (int i = 0; i < BLOCK; i++) {
                int at = block + i;
                byte plain = at < passwordLength ? password.getByte(passwordOffset + at) : 0;
                byte cipher = (byte) (plain ^ keystream[i]);
                out.putByte(outOffset + at, cipher);
                previous[i] = cipher;
            }
        }
        java.util.Arrays.fill(keystream, (byte) 0);
        return length;
    }

    /**
     * Verifies CHAP-Password = CHAP Identifier + {@code MD5(Identifier + password + challenge)}; the challenge is
     * CHAP-Challenge, or the Request Authenticator when the request has none. Constant-time comparison.
     *
     * @param password the user's cleartext password (CHAP cannot use a hash)
     * @return {@link #CHAP_MATCH}, {@link #CHAP_MISMATCH}, {@link #MISSING} or {@link #MALFORMED}
     */
    public int verifyChap(RadiusPacket request, DirectBuffer password, int passwordOffset, int passwordLength) {
        int response = single(request, CHAP_PASSWORD);
        if (response < 0) {
            return response;
        }
        DirectBuffer buffer = request.buffer();
        if ((buffer.getByte(response + 1) & 0xFF) - 2 != CHAP_RESPONSE_LENGTH) {
            return MALFORMED;
        }
        int challenge = single(request, CHAP_CHALLENGE);
        if (challenge == MALFORMED) {
            return MALFORMED;
        }
        md5.update(buffer.getByte(response + 2)); // CHAP Identifier
        updateFrom(password, passwordOffset, passwordLength);
        if (challenge == MISSING) {
            updateFrom(buffer, request.authenticatorOffset(), BLOCK);
        } else {
            int challengeLength = (buffer.getByte(challenge + 1) & 0xFF) - 2;
            if (challengeLength < 1) {
                md5.reset();
                return MALFORMED;
            }
            updateFrom(buffer, challenge + 2, challengeLength);
        }
        digest(keystream);
        int difference = 0;
        for (int i = 0; i < BLOCK; i++) {
            difference |= keystream[i] ^ buffer.getByte(response + 3 + i);
        }
        java.util.Arrays.fill(keystream, (byte) 0);
        return difference == 0 ? CHAP_MATCH : CHAP_MISMATCH;
    }

    /** Offset of the only attribute of {@code type}, {@link #MISSING}, or {@link #MALFORMED} if it occurs twice. */
    private static int single(RadiusPacket request, int type) {
        DirectBuffer buffer = request.buffer();
        int found = MISSING;
        for (int position = request.attributesOffset(); position < request.attributesEnd(); ) {
            if ((buffer.getByte(position) & 0xFF) == type) {
                if (found != MISSING) {
                    return MALFORMED;
                }
                found = position;
            }
            position += buffer.getByte(position + 1) & 0xFF;
        }
        return found;
    }

    private void updateFrom(DirectBuffer buffer, int offset, int length) {
        for (int done = 0; done < length; ) {
            int n = Math.min(value.length, length - done);
            buffer.getBytes(offset + done, value, 0, n);
            md5.update(value, 0, n);
            done += n;
        }
        java.util.Arrays.fill(value, (byte) 0);
    }

    private void digest(byte[] into) {
        try {
            md5.digest(into, 0, BLOCK);
        } catch (DigestException e) {
            throw new IllegalStateException(e); // a 16 byte buffer always fits an MD5 digest
        }
    }
}
