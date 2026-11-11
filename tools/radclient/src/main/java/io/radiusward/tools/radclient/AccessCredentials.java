/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacketEncoder;
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

    static final int MICROSOFT = 311;
    static final int MS_CHAP_CHALLENGE = 11;
    static final int MS_CHAP2_RESPONSE = 25;

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
                encoder.vendorAttribute(MICROSOFT, MS_CHAP_CHALLENGE, authenticatorChallenge);
                encoder.vendorAttribute(MICROSOFT, MS_CHAP2_RESPONSE, response);
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
        byte[] z = Arrays.copyOf(md4(password.getBytes(StandardCharsets.UTF_16LE)), 21);
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

    /** MD4 (RFC 1320), which the JDK does not offer; only for the NT password hash. */
    static byte[] md4(byte[] message) {
        long bits = (long) message.length * 8;
        int padded = ((message.length + 8) / 64 + 1) * 64;
        byte[] m = Arrays.copyOf(message, padded);
        m[message.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            m[padded - 8 + i] = (byte) (bits >>> (8 * i));
        }
        int a = 0x67452301;
        int b = 0xefcdab89;
        int c = 0x98badcfe;
        int d = 0x10325476;
        int[] x = new int[16];
        for (int block = 0; block < padded; block += 64) {
            for (int i = 0; i < 16; i++) {
                int o = block + i * 4;
                x[i] = (m[o] & 0xFF) | (m[o + 1] & 0xFF) << 8 | (m[o + 2] & 0xFF) << 16 | (m[o + 3] & 0xFF) << 24;
            }
            int aa = a;
            int bb = b;
            int cc = c;
            int dd = d;
            for (int i : new int[] {0, 4, 8, 12}) {
                a = Integer.rotateLeft(a + ((b & c) | (~b & d)) + x[i], 3);
                d = Integer.rotateLeft(d + ((a & b) | (~a & c)) + x[i + 1], 7);
                c = Integer.rotateLeft(c + ((d & a) | (~d & b)) + x[i + 2], 11);
                b = Integer.rotateLeft(b + ((c & d) | (~c & a)) + x[i + 3], 19);
            }
            for (int i : new int[] {0, 1, 2, 3}) {
                a = Integer.rotateLeft(a + ((b & c) | (b & d) | (c & d)) + x[i] + 0x5a827999, 3);
                d = Integer.rotateLeft(d + ((a & b) | (a & c) | (b & c)) + x[i + 4] + 0x5a827999, 5);
                c = Integer.rotateLeft(c + ((d & a) | (d & b) | (a & b)) + x[i + 8] + 0x5a827999, 9);
                b = Integer.rotateLeft(b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5a827999, 13);
            }
            for (int i : new int[] {0, 2, 1, 3}) {
                a = Integer.rotateLeft(a + (b ^ c ^ d) + x[i] + 0x6ed9eba1, 3);
                d = Integer.rotateLeft(d + (a ^ b ^ c) + x[i + 8] + 0x6ed9eba1, 9);
                c = Integer.rotateLeft(c + (d ^ a ^ b) + x[i + 4] + 0x6ed9eba1, 11);
                b = Integer.rotateLeft(b + (c ^ d ^ a) + x[i + 12] + 0x6ed9eba1, 15);
            }
            a += aa;
            b += bb;
            c += cc;
            d += dd;
        }
        byte[] out = new byte[16];
        int[] words = {a, b, c, d};
        for (int i = 0; i < 16; i++) {
            out[i] = (byte) (words[i / 4] >>> (8 * (i % 4)));
        }
        return out;
    }

    private static MessageDigest digest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm + " is part of every JDK", e);
        }
    }
}
