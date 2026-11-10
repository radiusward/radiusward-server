/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Verifies a PAP password against a stored credential, using the FreeRADIUS check-item names:
 *
 * <ul>
 *   <li>{@code Cleartext-Password} — compared in constant time; also what CHAP needs
 *   <li>{@code Crypt-Password} — {@code $5$} / {@code $6$} SHA-crypt ({@link ShaCrypt}), {@code $2a$} / {@code $2b$} /
 *       {@code $2y$} bcrypt ({@link BCrypt}), {@code $y$} yescrypt ({@link Yescrypt}), {@code $1$} MD5-crypt
 *       ({@link Md5Crypt})
 *   <li>{@code MD5-Password}, {@code SHA-Password} / {@code SHA1-Password}, {@code SHA2-Password} (224 to 512 by its
 *       length), {@code SHA2-224/256/384/512-Password} — unsalted digests, base64 or hex
 *   <li>{@code SMD5-Password} — salted MD5, like SSHA
 *   <li>{@code LM-Password} — the LAN Manager hash (32 hex digits); weak, for migration only
 *   <li>{@code SSHA-Password}, {@code SSHA2-224/256/384/512-Password} — salted SHA: base64 or hex of
 *       {@code digest || salt}
 *   <li>{@code NT-Password} — the NT hash (MD4 of the UTF-16LE password, 32 hex digits), as MS-CHAP uses it
 *   <li>{@code PBKDF2-Password} — {@code HMACSHA1|HMACSHA2+256|+384|+512 : iterations : salt : hash}, each part base64
 *       (iterations as a 4-byte big-endian number)
 * </ul>
 *
 * Other formats (argon2) are not verified: such a user is rejected. The legacy formats are accepted so that old
 * password databases can be migrated (ADR 0048).
 */
final class PasswordCheck {

    static final String CLEARTEXT = "Cleartext-Password";

    private PasswordCheck() {}

    /** Whether {@code attribute} holds a password this class can verify. */
    static boolean isPassword(String attribute) {
        return switch (attribute.toLowerCase(Locale.ROOT)) {
            case "cleartext-password",
                    "crypt-password",
                    "ssha-password",
                    "ssha2-224-password",
                    "ssha2-256-password",
                    "ssha2-384-password",
                    "ssha2-512-password",
                    "nt-password",
                    "pbkdf2-password",
                    "md5-password",
                    "smd5-password",
                    "sha-password",
                    "sha1-password",
                    "sha2-password",
                    "sha2-224-password",
                    "sha2-256-password",
                    "sha2-384-password",
                    "sha2-512-password",
                    "lm-password" -> true;
            default -> false;
        };
    }

    /** Whether a slow function stands behind it (worth caching a successful check). */
    static boolean isSlow(String attribute, String stored) {
        String a = attribute.toLowerCase(Locale.ROOT);
        return a.equals("pbkdf2-password") || a.equals("crypt-password");
    }

    /**
     * @return {@code true} if {@code password} matches; {@code false} if not, or the stored value is malformed or of an
     *     unsupported format
     */
    static boolean verify(String attribute, String stored, byte[] password) {
        return switch (attribute.toLowerCase(Locale.ROOT)) {
            case "cleartext-password" -> MessageDigest.isEqual(stored.getBytes(StandardCharsets.UTF_8), password);
            case "crypt-password" ->
                (ShaCrypt.supports(stored) && ShaCrypt.verify(password, stored))
                        || (BCrypt.supports(stored) && BCrypt.verify(password, stored))
                        || (Yescrypt.supports(stored) && Yescrypt.verify(password, stored))
                        || (Md5Crypt.supports(stored) && Md5Crypt.verify(password, stored));
            case "md5-password" -> plain("MD5", stored, password);
            case "smd5-password" -> salted("MD5", stored, password);
            case "sha-password", "sha1-password" -> plain("SHA-1", stored, password);
            case "sha2-224-password" -> plain("SHA-224", stored, password);
            case "sha2-256-password" -> plain("SHA-256", stored, password);
            case "sha2-384-password" -> plain("SHA-384", stored, password);
            case "sha2-512-password" -> plain("SHA-512", stored, password);
            case "sha2-password" -> sha2(stored, password);
            case "lm-password" -> lm(stored, password);
            case "ssha-password" -> salted("SHA-1", stored, password);
            case "ssha2-224-password" -> salted("SHA-224", stored, password);
            case "ssha2-256-password" -> salted("SHA-256", stored, password);
            case "ssha2-384-password" -> salted("SHA-384", stored, password);
            case "ssha2-512-password" -> salted("SHA-512", stored, password);
            case "pbkdf2-password" -> pbkdf2(stored, password);
            case "nt-password" -> nt(stored, password);
            default -> false;
        };
    }

    /** An unsalted digest of the password, base64 or hex. */
    private static boolean plain(String algorithm, String stored, byte[] password) {
        byte[] value = decode(stored.trim());
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            return value != null
                    && value.length == md.getDigestLength()
                    && MessageDigest.isEqual(md.digest(password), value);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** SHA2-Password: the SHA-2 variant follows from the digest's length. */
    private static boolean sha2(String stored, byte[] password) {
        byte[] value = decode(stored.trim());
        if (value == null) {
            return false;
        }
        String algorithm = switch (value.length) {
            case 28 -> "SHA-224";
            case 32 -> "SHA-256";
            case 48 -> "SHA-384";
            case 64 -> "SHA-512";
            default -> null;
        };
        return algorithm != null && plain(algorithm, stored, password);
    }

    /**
     * The LAN Manager hash: the password upper-cased (OEM characters, at most 14), split in two 7-byte DES keys that
     * each encrypt {@code KGS!@#$%}.
     */
    private static boolean lm(String stored, byte[] password) {
        String text = stored.trim();
        if (text.length() != 32 || !text.matches("[0-9A-Fa-f]+")) {
            return false;
        }
        char[] chars = utf8(password);
        if (chars == null || chars.length > 14) {
            return false;
        }
        byte[] key = new byte[14];
        for (int i = 0; i < chars.length; i++) {
            char c = Character.toUpperCase(chars[i]);
            if (c > 0x7F) {
                Arrays.fill(chars, '\0');
                return false; // beyond ASCII the OEM code page is unknown
            }
            key[i] = (byte) c;
        }
        Arrays.fill(chars, '\0');
        byte[] magic = "KGS!@#$%".getBytes(StandardCharsets.US_ASCII);
        byte[] hash = new byte[16];
        System.arraycopy(MsChap.des(Arrays.copyOfRange(key, 0, 7), magic), 0, hash, 0, 8);
        System.arraycopy(MsChap.des(Arrays.copyOfRange(key, 7, 14), magic), 0, hash, 8, 8);
        Arrays.fill(key, (byte) 0);
        return MessageDigest.isEqual(hash, HexFormat.of().parseHex(text));
    }

    private static boolean salted(String algorithm, String stored, byte[] password) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] value = decode(stored.trim());
            int size = md.getDigestLength();
            if (value == null || value.length <= size) {
                return false;
            }
            md.update(password);
            md.update(value, size, value.length - size);
            return MessageDigest.isEqual(md.digest(), Arrays.copyOf(value, size));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Hex if it is even-length hex, else base64; {@code null} if neither. */
    private static byte[] decode(String text) {
        if (text.length() % 2 == 0 && text.matches("[0-9A-Fa-f]+")) {
            return HexFormat.of().parseHex(text);
        }
        try {
            return Base64.getDecoder().decode(text);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean pbkdf2(String stored, byte[] password) {
        String[] parts = stored.trim().split(":");
        if (parts.length != 4) {
            return false;
        }
        String algorithm = switch (parts[0].toUpperCase(Locale.ROOT)) {
            case "HMACSHA1" -> "PBKDF2WithHmacSHA1";
            case "HMACSHA2+256" -> "PBKDF2WithHmacSHA256";
            case "HMACSHA2+384" -> "PBKDF2WithHmacSHA384";
            case "HMACSHA2+512" -> "PBKDF2WithHmacSHA512";
            default -> null;
        };
        if (algorithm == null) {
            return false;
        }
        try {
            byte[] iterationBytes = Base64.getDecoder().decode(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            if (iterationBytes.length != 4 || expected.length == 0) {
                return false;
            }
            int iterations = ByteBuffer.wrap(iterationBytes).getInt();
            if (iterations < 1 || iterations > 10_000_000) {
                return false;
            }
            char[] chars = utf8(password);
            if (chars == null) {
                return false;
            }
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, expected.length * 8);
            try {
                byte[] actual = SecretKeyFactory.getInstance(algorithm)
                        .generateSecret(spec)
                        .getEncoded();
                return MessageDigest.isEqual(actual, expected);
            } finally {
                spec.clearPassword();
                Arrays.fill(chars, '\0');
            }
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    private static boolean nt(String stored, byte[] password) {
        byte[] expected = MsChap.parseNtPassword(stored);
        char[] chars = utf8(password);
        if (expected == null || chars == null) {
            return false;
        }
        byte[] utf16 = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++) {
            utf16[2 * i] = (byte) chars[i];
            utf16[2 * i + 1] = (byte) (chars[i] >>> 8);
        }
        boolean match = MessageDigest.isEqual(Md4.digest(utf16), expected);
        Arrays.fill(chars, '\0');
        Arrays.fill(utf16, (byte) 0);
        return match;
    }

    private static char[] utf8(byte[] password) {
        try {
            var buffer = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(password));
            char[] chars = new char[buffer.remaining()];
            buffer.get(chars);
            return chars;
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
