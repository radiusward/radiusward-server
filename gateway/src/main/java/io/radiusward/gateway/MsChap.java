/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * The calculations of MS-CHAP: version 1 (RFC 2433), version 2 (RFC 2759), its MPPE keys (RFC 3079) and the encryption
 * of key attributes in RADIUS (RFC 2548). Verification only, from the NT password hash.
 */
final class MsChap {

    private static final byte[] MAGIC_SIGN = ascii("Magic server to client signing constant");
    private static final byte[] MAGIC_PAD = ascii("Pad to make it do more than one iteration");
    private static final byte[] MAGIC_MASTER = ascii("This is the MPPE Master Key");
    private static final byte[] MAGIC_CLIENT_SEND =
            ascii("On the client side, this is the send key; on the server side, it is the receive key.");
    private static final byte[] MAGIC_CLIENT_RECEIVE =
            ascii("On the client side, this is the receive key; on the server side, it is the send key.");
    private static final byte[] PAD_ZEROS = new byte[40];
    private static final byte[] PAD_F2 = filled(40, (byte) 0xF2);

    private MsChap() {}

    /** NtPasswordHash: MD4 of the password in UTF-16LE. */
    static byte[] ntHash(String password) {
        return Md4.digest(password.getBytes(StandardCharsets.UTF_16LE));
    }

    /** {@code NT-Password} as stored: 32 hex digits, optionally with {@code 0x}; {@code null} if malformed. */
    static byte[] parseNtPassword(String value) {
        String hex = value.trim();
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        if (hex.length() != 32) {
            return null;
        }
        try {
            return HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** ChallengeResponse: three DES encryptions of the 8-byte challenge with keys from the zero-padded hash. */
    static byte[] challengeResponse(byte[] challenge, byte[] ntHash) {
        byte[] z = Arrays.copyOf(ntHash, 21);
        byte[] out = new byte[24];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(des(Arrays.copyOfRange(z, i * 7, i * 7 + 7), challenge), 0, out, i * 8, 8);
        }
        return out;
    }

    /** MS-CHAPv2 ChallengeHash: SHA-1 of peer challenge, authenticator challenge and user name (no domain). */
    static byte[] challengeHash(byte[] peerChallenge, byte[] authenticatorChallenge, byte[] userName) {
        MessageDigest sha = sha1();
        sha.update(peerChallenge);
        sha.update(authenticatorChallenge);
        sha.update(userName);
        return Arrays.copyOf(sha.digest(), 8);
    }

    /** The user name as MS-CHAPv2 hashes it: without a {@code DOMAIN\} prefix. */
    static byte[] v2UserName(byte[] userName) {
        for (int i = userName.length - 1; i >= 0; i--) {
            if (userName[i] == '\\') {
                return Arrays.copyOfRange(userName, i + 1, userName.length);
            }
        }
        return userName;
    }

    /** MS-CHAPv2 GenerateAuthenticatorResponse: {@code S=} and 40 upper-case hex digits. */
    static String authenticatorResponse(byte[] ntHash, byte[] ntResponse, byte[] challengeHash) {
        return authenticatorResponseFromKey(Md4.digest(ntHash), ntResponse, challengeHash);
    }

    /** As above, from the hash of the NT hash (the user session key a domain controller returns). */
    static String authenticatorResponseFromKey(byte[] ntHashHash, byte[] ntResponse, byte[] challengeHash) {
        MessageDigest sha = sha1();
        sha.update(ntHashHash);
        sha.update(ntResponse);
        sha.update(MAGIC_SIGN);
        byte[] digest = sha.digest();
        sha.update(digest);
        sha.update(challengeHash);
        sha.update(MAGIC_PAD);
        return "S=" + HexFormat.of().formatHex(sha.digest()).toUpperCase(Locale.ROOT);
    }

    /** RFC 3079 MasterKey of an MS-CHAPv2 exchange. */
    static byte[] masterKey(byte[] ntHash, byte[] ntResponse) {
        return masterKeyFromKey(Md4.digest(ntHash), ntResponse);
    }

    /** As above, from the hash of the NT hash. */
    static byte[] masterKeyFromKey(byte[] ntHashHash, byte[] ntResponse) {
        MessageDigest sha = sha1();
        sha.update(ntHashHash);
        sha.update(ntResponse);
        sha.update(MAGIC_MASTER);
        return Arrays.copyOf(sha.digest(), 16);
    }

    /** RFC 3079 GetAsymmetricStartKey for the server (the NAS): its send or its receive key, 128 bits. */
    static byte[] serverKey(byte[] masterKey, boolean send) {
        MessageDigest sha = sha1();
        sha.update(masterKey);
        sha.update(PAD_ZEROS);
        sha.update(send ? MAGIC_CLIENT_RECEIVE : MAGIC_CLIENT_SEND);
        sha.update(PAD_F2);
        return Arrays.copyOf(sha.digest(), 16);
    }

    /**
     * RFC 2548 §2.4.2 (MS-MPPE-Send-Key, MS-MPPE-Recv-Key): salt, then the key's length, the key and zero padding to
     * a multiple of 16, each block XORed with MD5(secret, previous block or request authenticator and salt).
     *
     * @param salt two bytes, the first with its high bit set, unique within the packet
     */
    static byte[] encryptKey(byte[] key, byte[] secret, byte[] requestAuthenticator, byte[] salt) {
        byte[] plain = new byte[((key.length + 1 + 15) / 16) * 16];
        plain[0] = (byte) key.length;
        System.arraycopy(key, 0, plain, 1, key.length);
        byte[] out = new byte[2 + plain.length];
        out[0] = salt[0];
        out[1] = salt[1];
        hide(plain, secret, requestAuthenticator, salt, out, 2);
        return out;
    }

    /**
     * RFC 2548 §2.4.1 (MS-CHAP-MPPE-Keys of MS-CHAPv1): the 8-byte LAN Manager key, the 16-byte NT key and 8 zero
     * bytes, hidden like User-Password (RFC 2865 §5.2) with the request authenticator.
     */
    static byte[] encryptV1Keys(byte[] lmKey, byte[] ntKey, byte[] secret, byte[] requestAuthenticator) {
        byte[] plain = new byte[32];
        System.arraycopy(lmKey, 0, plain, 0, 8);
        System.arraycopy(ntKey, 0, plain, 8, 16);
        byte[] out = new byte[32];
        hide(plain, secret, requestAuthenticator, new byte[0], out, 0);
        return out;
    }

    private static void hide(byte[] plain, byte[] secret, byte[] authenticator, byte[] salt, byte[] out, int at) {
        MessageDigest md5 = md5();
        byte[] previous = null;
        for (int block = 0; block < plain.length; block += 16) {
            md5.update(secret);
            if (previous == null) {
                md5.update(authenticator);
                md5.update(salt);
            } else {
                md5.update(previous);
            }
            byte[] b = md5.digest();
            previous = new byte[16];
            for (int i = 0; i < 16; i++) {
                previous[i] = (byte) (plain[block + i] ^ b[i]);
            }
            System.arraycopy(previous, 0, out, at + block, 16);
        }
    }

    /** DES with a 56-bit key (7 bytes spread over 8, parity bits left to the cipher). */
    private static byte[] des(byte[] key7, byte[] block) {
        byte[] key = new byte[8];
        key[0] = (byte) (key7[0] & 0xFE);
        key[1] = (byte) ((key7[0] << 7 | (key7[1] & 0xFF) >>> 1) & 0xFE);
        key[2] = (byte) ((key7[1] << 6 | (key7[2] & 0xFF) >>> 2) & 0xFE);
        key[3] = (byte) ((key7[2] << 5 | (key7[3] & 0xFF) >>> 3) & 0xFE);
        key[4] = (byte) ((key7[3] << 4 | (key7[4] & 0xFF) >>> 4) & 0xFE);
        key[5] = (byte) ((key7[4] << 3 | (key7[5] & 0xFF) >>> 5) & 0xFE);
        key[6] = (byte) ((key7[5] << 2 | (key7[6] & 0xFF) >>> 6) & 0xFE);
        key[7] = (byte) (key7[6] << 1 & 0xFE);
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            return cipher.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("DES is part of every JDK", e);
        }
    }

    private static MessageDigest sha1() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static MessageDigest md5() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] filled(int n, byte value) {
        byte[] b = new byte[n];
        Arrays.fill(b, value);
        return b;
    }
}
