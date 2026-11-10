/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * yescrypt (ADR 0048) against the reference implementation's known answers (TESTS-OK of openwall/yescrypt) and hashes
 * made by Debian's {@code mkpasswd -m yescrypt} (libxcrypt), which take the pre-hash path.
 */
class YescryptTest {

    static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    @Test
    void classicScryptAndTheKdf() {
        assertThat(Yescrypt.kdf(b(""), b(""), 0, 16, 1, 1, 0, 64))
                .as("scrypt(\"\", \"\", 16, 1, 1)")
                .isEqualTo(hex("77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed"
                        + " e2 14 42 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2"
                        + " 0c 38 d1 89 06"));
        assertThat(Yescrypt.kdf(b("p"), b("s"), 182, 16, 8, 1, 0, 32))
                .as("yescrypt(\"p\", \"s\", 182, 16, 8, 1, 0, 0)")
                .isEqualTo(hex("c8 c7 ff 11 22 b0 b2 91 c3 f2 60 89 48 78 2c d6 89 cc 45 57 90 17 aa a5 ff 8b aa 74 a6"
                        + " 32 ec 99"));
        assertThat(Yescrypt.kdf(b("p"), b("s"), 182, 16, 8, 1, 0, 8)).isEqualTo(hex("c8 c7 ff 11 22 b0 b2 91"));
    }

    @Test
    void theReferenceHashes() {
        for (String hash : new String[] {
            "$y$j0/$LdJM$k7BXzSDuoGHW56SY3HxROCiA0gWRscZe2aA0q5oHPM0",
            "$y$///$L/$Rrrkp6OVljrIk0kcwkCDhAiHJiSthh3cKeIGHUW7Z0C",
            "$y$j//$LdJMENpBABJJ3hIHjB1B$U8a2MaK.yesqWySK8Owk6PWeWmp/XuagMbpP45q1/q1",
            "$y$j4/$LdJMENpBA/$tHlkpTQ8V/eEnTVau1uW36T97LIXlfPrEzdeV5SE5K7",
            "$y$j5..3$LdJMENpBAB3$xi27PTUNd8NsChHeLOz85JFnUOyibRHkWzprowRlR5/",
            "$y$j1../$LdJMENpBABJJ3hIHjB1Bi.$L8OQFc8mxJPd7CpUFgkS7KqJM2I9jGXu3BdqX2D.647",
            "$y$j80$LdJMENpBABJJ3h2$ysXVVJwuaVlI1BWoEKt/Bz3WNDDmdOWz/8KTQaHL1cC",
            "$y$/A2$LdJMENpBABJJ3hIHj/$5IEld1eWdmh5lylrqHLF5dvA3ISpimEM9J1Dd05n/.3",
            "$y$j91.5$LdJMENpBABJJ3hIH$ebKnn23URD5vyLgF9cP2EvVosrUXf7UErGRV0KmC6e6"
        }) {
            assertThat(Yescrypt.crypt(b("pleaseletmein"), hash)).as(hash).isEqualTo(hash);
            assertThat(Yescrypt.verify(b("pleaseletmein"), hash)).isTrue();
            assertThat(Yescrypt.verify(b("pleaseletmeout"), hash)).isFalse();
        }
    }

    @Test
    void hashesOfDebiansMkpasswd() {
        assertThat(Yescrypt.verify(
                        b("Alice-Passw0rd!"),
                        "$y$j9T$y51woau7Tip9DgZxbPSuH1$rewuM6kL2JSqLpR0Qtu9t.zrnkDD4uHh3U60ETllJ66"))
                .as("the default j9T: N 4096, r 32, with the pre-hash")
                .isTrue();
        assertThat(Yescrypt.verify(
                        b("s3cret"), "$y$jBT$zRSEvhviYySFifUafj4Qq/$2Zjbp7fWYJL3RVwBXFPZCDQogWqqKBcYg3.ZFK032k2"))
                .isTrue();
        assertThat(Yescrypt.verify(
                        b("wrong"), "$y$j9T$y51woau7Tip9DgZxbPSuH1$rewuM6kL2JSqLpR0Qtu9t.zrnkDD4uHh3U60ETllJ66"))
                .isFalse();
    }

    @Test
    void malformedOrUnsupportedSettingsAreRejected() {
        for (String bad : new String[] {
            "$1$abc$def", // not yescrypt
            "$y$", // nothing
            "$y$j", // no N
            "$y$j9T", // no salt
            "$y$j9T$!!!$x", // salt outside the alphabet
            "$y$~9T$abc$x", // flavor outside the alphabet
            "$y$jzT$abcd$x", // N too large for the memory limit
            "$y$j9T4/$abcd$x" // hash upgrades (g) or a ROM
        }) {
            assertThat(Yescrypt.verify(b("x"), bad)).as(bad).isFalse();
        }
        assertThat(Yescrypt.supports("$y$j9T$x$y")).isTrue();
        assertThat(Yescrypt.supports("$6$x$y")).isFalse();
        assertThat(Yescrypt.decode64("abc"))
                .as("non-zero bits beyond the bytes")
                .isNull();
        assertThat(Yescrypt.encode64(Yescrypt.decode64("LdJMENpBABJJ3hIHjB1Bi.")))
                .isEqualTo("LdJMENpBABJJ3hIHjB1Bi.");
    }
}
