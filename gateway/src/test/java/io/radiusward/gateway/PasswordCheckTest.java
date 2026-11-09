/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class PasswordCheckTest {

    static final byte[] PASSWORD = "arctangent".getBytes(StandardCharsets.UTF_8);
    static final byte[] SALT = {1, 2, 3, 4, 5, 6, 7, 8};

    /** digest(password || salt) || salt — computed here independently of the code under test. */
    static byte[] salted(String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        md.update(PASSWORD);
        md.update(SALT);
        byte[] digest = md.digest();
        byte[] out = new byte[digest.length + SALT.length];
        System.arraycopy(digest, 0, out, 0, digest.length);
        System.arraycopy(SALT, 0, out, digest.length, SALT.length);
        return out;
    }

    @Test
    void cleartext() {
        assertThat(PasswordCheck.verify("Cleartext-Password", "arctangent", PASSWORD))
                .isTrue();
        assertThat(PasswordCheck.verify("cleartext-password", "arctangent", PASSWORD))
                .as("case-insensitive name")
                .isTrue();
        assertThat(PasswordCheck.verify("Cleartext-Password", "arctangenT", PASSWORD))
                .isFalse();
        assertThat(PasswordCheck.verify("Cleartext-Password", "", PASSWORD)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
        "SSHA-Password, SHA-1",
        "SSHA2-224-Password, SHA-224",
        "SSHA2-256-Password, SHA-256",
        "SSHA2-384-Password, SHA-384",
        "SSHA2-512-Password, SHA-512"
    })
    void saltedShaInBase64AndHex(String attribute, String algorithm) throws Exception {
        byte[] value = salted(algorithm);
        assertThat(PasswordCheck.verify(attribute, Base64.getEncoder().encodeToString(value), PASSWORD))
                .isTrue();
        assertThat(PasswordCheck.verify(attribute, HexFormat.of().formatHex(value), PASSWORD))
                .isTrue();
        assertThat(PasswordCheck.verify(attribute, Base64.getEncoder().encodeToString(value), "x".getBytes()))
                .isFalse();
        assertThat(PasswordCheck.verify(attribute, "!!not base64!!", PASSWORD)).isFalse();
        assertThat(PasswordCheck.verify(attribute, "AAAA", PASSWORD))
                .as("too short")
                .isFalse();
    }

    @ParameterizedTest
    @CsvSource({
        "HMACSHA1, PBKDF2WithHmacSHA1",
        "HMACSHA2+256, PBKDF2WithHmacSHA256",
        "HMACSHA2+512, PBKDF2WithHmacSHA512"
    })
    void pbkdf2(String prefix, String algorithm) throws Exception {
        int iterations = 10_000;
        byte[] hash = SecretKeyFactory.getInstance(algorithm)
                .generateSecret(new PBEKeySpec("arctangent".toCharArray(), SALT, iterations, 256))
                .getEncoded();
        Base64.Encoder b64 = Base64.getEncoder();
        String stored = prefix + ":"
                + b64.encodeToString(ByteBuffer.allocate(4).putInt(iterations).array()) + ":" + b64.encodeToString(SALT)
                + ":" + b64.encodeToString(hash);
        assertThat(PasswordCheck.verify("PBKDF2-Password", stored, PASSWORD)).isTrue();
        assertThat(PasswordCheck.verify("PBKDF2-Password", stored, "wrong".getBytes()))
                .isFalse();
        assertThat(PasswordCheck.isSlow("PBKDF2-Password", stored)).isTrue();
    }

    @Test
    void malformedAndUnsupportedFormatsNeverMatch() {
        assertThat(PasswordCheck.verify("PBKDF2-Password", "HMACMD5:AAAnEA==:AQID:AQID", PASSWORD))
                .isFalse();
        assertThat(PasswordCheck.verify("PBKDF2-Password", "HMACSHA1:AAA=:AQID:AQID", PASSWORD))
                .isFalse();
        assertThat(PasswordCheck.verify("PBKDF2-Password", "only:three:parts", PASSWORD))
                .isFalse();
        assertThat(PasswordCheck.verify("PBKDF2-Password", "HMACSHA1:AAAAAA==:AQID:AQID", PASSWORD))
                .as("zero iterations")
                .isFalse();
        assertThat(PasswordCheck.verify("Crypt-Password", "$2y$10$abcdefghijklmnopqrstuu", PASSWORD))
                .as("malformed bcrypt")
                .isFalse();
        assertThat(PasswordCheck.verify(
                        "Crypt-Password",
                        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
                        PASSWORD))
                .as("argon2: not supported")
                .isFalse();
        assertThat(PasswordCheck.verify("LM-Password", "E52CAC67419A9A224A3B108F3FA6CB6D", PASSWORD))
                .isFalse();
        assertThat(PasswordCheck.isPassword("LM-Password")).isFalse();
        assertThat(PasswordCheck.isPassword("Crypt-Password")).isTrue();
        assertThat(PasswordCheck.verify("PBKDF2-Password", "HMACSHA2+256:AAAnEA==:AQID:AQID", new byte[] {(byte) 0xff}))
                .as("not UTF-8")
                .isFalse();
    }

    @Test
    void shaCryptThroughTheCheck() {
        String stored = ShaCrypt.crypt(PASSWORD, "$6$rounds=1000$somesalt");
        assertThat(PasswordCheck.verify("Crypt-Password", stored, PASSWORD)).isTrue();
        assertThat(PasswordCheck.verify("Crypt-Password", stored, "x".getBytes()))
                .isFalse();
    }

    @Test
    void ntPasswordForPap() {
        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        assertThat(PasswordCheck.verify("NT-Password", "8846F7EAEE8FB117AD06BDD830B7586C", password))
                .isTrue();
        assertThat(PasswordCheck.verify("NT-Password", "0x8846f7eaee8fb117ad06bdd830b7586c", password))
                .isTrue();
        assertThat(PasswordCheck.verify("NT-Password", "8846F7EAEE8FB117AD06BDD830B7586C", PASSWORD))
                .isFalse();
        assertThat(PasswordCheck.verify("NT-Password", "8846F7", password))
                .as("malformed")
                .isFalse();
        assertThat(PasswordCheck.verify(
                        "NT-Password",
                        HexFormat.of().formatHex(MsChap.ntHash("pässwörd")),
                        "pässwörd".getBytes(StandardCharsets.UTF_8)))
                .as("non-ASCII in UTF-16LE")
                .isTrue();
    }
}
