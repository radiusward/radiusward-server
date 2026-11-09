/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Known-answer vectors of RFC 1320 (MD4), RFC 2759 §9.2 (MS-CHAPv2) and RFC 3079 §3.5.3 (MPPE keys). */
class MsChapTest {

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b).toUpperCase(java.util.Locale.ROOT);
    }

    @ParameterizedTest
    @CsvSource({
        "'', 31d6cfe0d16ae931b73c59d7e0c089c0",
        "a, bde52cb31de33e46245e05fbdbd6fb24",
        "abc, a448017aaf21d8525fc10ae87aa6729d",
        "message digest, d9130a8164549fe818874806e1c7014b",
        "abcdefghijklmnopqrstuvwxyz, d79e1c308aa5bbcdeea8ed63df412da9",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890,"
                + " e33b4ddc9c38f2199c3e7b164fcc0536"
    })
    void md4(String message, String digest) {
        assertThat(HexFormat.of().formatHex(Md4.digest(message.getBytes(StandardCharsets.US_ASCII))))
                .isEqualTo(digest);
    }

    @Test
    void ntHash() {
        assertThat(hex(MsChap.ntHash("password"))).isEqualTo("8846F7EAEE8FB117AD06BDD830B7586C");
        assertThat(hex(MsChap.parseNtPassword("0x8846f7eaee8fb117ad06bdd830b7586c")))
                .isEqualTo("8846F7EAEE8FB117AD06BDD830B7586C");
        assertThat(MsChap.parseNtPassword("8846F7")).isNull();
        assertThat(MsChap.parseNtPassword("zz46F7EAEE8FB117AD06BDD830B7586C")).isNull();
    }

    @Test
    void rfc2759() {
        byte[] user = "User".getBytes(StandardCharsets.US_ASCII);
        byte[] authChallenge = hex("5B5D7C7D7B3F2F3E3C2C602132262628");
        byte[] peerChallenge = hex("21402324255E262A28295F2B3A337C7E");
        byte[] challenge = MsChap.challengeHash(peerChallenge, authChallenge, user);
        assertThat(hex(challenge)).isEqualTo("D02E4386BCE91226");
        byte[] hash = MsChap.ntHash("clientPass");
        assertThat(hex(hash)).isEqualTo("44EBBA8D5312B8D611474411F56989AE");
        assertThat(hex(Md4.digest(hash))).isEqualTo("41C00C584BD2D91C4017A2A12FA59F3F");
        byte[] response = MsChap.challengeResponse(challenge, hash);
        assertThat(hex(response)).isEqualTo("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
        assertThat(MsChap.authenticatorResponse(hash, response, challenge))
                .isEqualTo("S=407A5589115FD0D6209F510FE9C04566932CDA56");
        assertThat(MsChap.v2UserName("CORP\\User".getBytes(StandardCharsets.US_ASCII)))
                .isEqualTo(user);
    }

    @Test
    void rfc3079() {
        byte[] hash = MsChap.ntHash("clientPass");
        byte[] response = hex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF");
        byte[] master = MsChap.masterKey(hash, response);
        assertThat(hex(master)).isEqualTo("FDECE3717A8C838CB388E527AE3CDD31");
        assertThat(hex(MsChap.serverKey(master, true))).isEqualTo("8B7CDC149B993A1BA118CB153F56DCCB");
    }

    /** RFC 2548 §2.4.2, reversed independently: the receiver recovers the key. */
    @Test
    void mppeKeyEncryption() throws Exception {
        byte[] key = hex("8B7CDC149B993A1BA118CB153F56DCCB");
        byte[] secret = "s3cret".getBytes(StandardCharsets.US_ASCII);
        byte[] auth = hex("000102030405060708090a0b0c0d0e0f");
        byte[] salt = {(byte) 0x81, 0x23};
        byte[] encrypted = MsChap.encryptKey(key, secret, auth, salt);
        assertThat(encrypted).hasSize(2 + 32);
        assertThat(encrypted[0]).isEqualTo(salt[0]);
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(secret);
        md5.update(auth);
        md5.update(salt);
        byte[] b1 = md5.digest();
        byte[] p1 = new byte[16];
        for (int i = 0; i < 16; i++) {
            p1[i] = (byte) (encrypted[2 + i] ^ b1[i]);
        }
        md5.update(secret);
        md5.update(encrypted, 2, 16);
        byte[] b2 = md5.digest();
        byte[] p2 = new byte[16];
        for (int i = 0; i < 16; i++) {
            p2[i] = (byte) (encrypted[18 + i] ^ b2[i]);
        }
        assertThat(p1[0]).as("key length").isEqualTo((byte) 16);
        byte[] recovered = new byte[16];
        System.arraycopy(p1, 1, recovered, 0, 15);
        recovered[15] = p2[0];
        assertThat(recovered).isEqualTo(key);
        assertThat(java.util.Arrays.copyOfRange(p2, 1, 16)).as("zero padding").containsOnly(0);
    }
}
