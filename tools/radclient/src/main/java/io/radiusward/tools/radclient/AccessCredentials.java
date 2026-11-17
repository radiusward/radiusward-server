/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.auth.Md4;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.codec.attributes.Microsoft;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The credential attributes of an Access-Request, as a NAS writes them: PAP (RFC 2865 §5.2), CHAP (RFC 1994, RFC 2865
 * §5.3) and MS-CHAPv2 (RFC 2759, RFC 2548 §2.3). The MD4 and DES of MS-CHAP are fixed by the protocol.
 */
final class AccessCredentials {

    enum Method {
        PAP,
        CHAP,
        MSCHAPV2;

        static Method parse(String name) {
            return switch (name.trim().toLowerCase(Locale.ROOT)) {
                case "pap" -> PAP;
                case "chap" -> CHAP;
                case "mschapv2", "mschap2", "ms-chapv2" -> MSCHAPV2;
                default -> throw new UsageException("unknown method " + name + " (pap|chap|mschapv2)");
            };
        }
    }

    private final Random random;
    private final AccessRequests requests = new AccessRequests();
    private final UnsafeBuffer encrypted = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);

    /** @param random the source of challenges; a {@link java.security.SecureRandom} outside tests and load */
    AccessCredentials(Random random) {
        this.random = random;
    }

    /** Writes User-Password, CHAP-Password and CHAP-Challenge, or MS-CHAP-Challenge and MS-CHAP2-Response. */
    void write(
            RadiusPacketEncoder encoder,
            byte[] requestAuthenticator,
            String user,
            String password,
            Method method,
            byte[] secret) {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        switch (method) {
            case PAP -> {
                int length = requests.encryptUserPassword(
                        new UnsafeBuffer(pw),
                        0,
                        pw.length,
                        new UnsafeBuffer(requestAuthenticator),
                        0,
                        secret,
                        encrypted,
                        0);
                if (length < 0) {
                    throw new UsageException("a PAP password is at most " + AccessRequests.MAX_PASSWORD + " bytes");
                }
                encoder.attribute(AccessRequests.USER_PASSWORD, encrypted, 0, length);
            }
            case CHAP -> {
                byte[] challenge = bytes(16);
                int identifier = random.nextInt(256);
                encoder.attribute(AccessRequests.CHAP_PASSWORD, chapPassword(identifier, pw, challenge));
                encoder.attribute(AccessRequests.CHAP_CHALLENGE, challenge);
            }
            case MSCHAPV2 -> {
                byte[] authenticatorChallenge = bytes(16);
                byte[] peerChallenge = bytes(16);
                byte[] response = new byte[50]; // Ident, Flags, Peer-Challenge, 8 reserved, NT-Response
                response[0] = (byte) random.nextInt(256);
                System.arraycopy(peerChallenge, 0, response, 2, 16);
                System.arraycopy(
                        ntResponse(authenticatorChallenge, peerChallenge, user, password), 0, response, 26, 24);
                encoder.vendorAttribute(Microsoft.VENDOR_ID, Microsoft.CHAP_CHALLENGE, authenticatorChallenge);
                encoder.vendorAttribute(Microsoft.VENDOR_ID, Microsoft.CHAP2_RESPONSE, response);
            }
        }
    }

    private byte[] bytes(int n) {
        byte[] b = new byte[n];
        random.nextBytes(b);
        return b;
    }

    /** CHAP Identifier, then {@code MD5(Identifier + password + challenge)}. */
    static byte[] chapPassword(int identifier, byte[] password, byte[] challenge) {
        MessageDigest md5 = digest("MD5");
        md5.update((byte) identifier);
        md5.update(password);
        md5.update(challenge);
        byte[] out = new byte[17];
        out[0] = (byte) identifier;
        System.arraycopy(md5.digest(), 0, out, 1, 16);
        return out;
    }

    /** RFC 2759 GenerateNTResponse: ChallengeHash, then ChallengeResponse with the NT password hash. */
    static byte[] ntResponse(byte[] authenticatorChallenge, byte[] peerChallenge, String user, String password) {
        MessageDigest sha = digest("SHA-1");
        sha.update(peerChallenge);
        sha.update(authenticatorChallenge);
        sha.update(userWithoutDomain(user).getBytes(StandardCharsets.UTF_8));
        byte[] challenge = Arrays.copyOf(sha.digest(), 8);
        byte[] z = Arrays.copyOf(Md4.digest(password.getBytes(StandardCharsets.UTF_16LE)), 21);
        byte[] out = new byte[24];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(des(Arrays.copyOfRange(z, i * 7, i * 7 + 7), challenge), 0, out, i * 8, 8);
        }
        return out;
    }

    private static String userWithoutDomain(String user) {
        int slash = user.lastIndexOf('\\');
        return slash < 0 ? user : user.substring(slash + 1);
    }

    /** DES with a 56-bit key spread over 8 bytes (parity bits left to the cipher). */
    private static byte[] des(byte[] key7, byte[] block) {
        byte[] key = new byte[8];
        key[0] = (byte) (key7[0] & 0xFE);
        for (int i = 1; i < 7; i++) {
            key[i] = (byte) ((key7[i - 1] << (8 - i) | (key7[i] & 0xFF) >>> i) & 0xFE);
        }
        key[7] = (byte) (key7[6] << 1 & 0xFE);
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            return cipher.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("DES is part of every JDK", e);
        }
    }

    private static MessageDigest digest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm + " is part of every JDK", e);
        }
    }
}
