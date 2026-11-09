/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class BCryptTest {

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Published vectors (the OpenBSD / jBCrypt set). */
    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            value = {
                "''|$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.",
                "a|$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe",
                "abc|$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i",
                "abcdefghijklmnopqrstuvwxyz|$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC",
                "~!@#$%^&*()      ~!@#$%^&*()PNBFRD|$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"
            })
    void knownAnswers(String password, String hash) {
        assertThat(BCrypt.verify(utf8(password), hash)).isTrue();
        assertThat(BCrypt.verify(utf8(password + "x"), hash)).isFalse();
        for (String prefix : new String[] {"$2b$", "$2y$"}) {
            assertThat(BCrypt.verify(utf8(password), prefix + hash.substring(4)))
                    .as(prefix)
                    .isTrue();
        }
    }

    /** Random passwords (any bytes) and salts at the lowest cost against an independent implementation. */
    @Test
    void agreesWithAReferenceImplementation() {
        Random random = new Random(20261109);
        for (int i = 0; i < 300; i++) {
            byte[] password = new byte[random.nextInt(72)];
            random.nextBytes(password);
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            String version = new String[] {"2a", "2b", "2y"}[i % 3];
            String hash = OpenBSDBCrypt.generate(version, password, salt, 4);
            assertThat(BCrypt.verify(password, hash)).as(hash).isTrue();
            if (password.length > 0) {
                byte[] wrong = password.clone();
                wrong[random.nextInt(wrong.length)] ^= (byte) (1 << random.nextInt(8));
                assertThat(BCrypt.verify(wrong, hash))
                        .as("one bit off: " + hash)
                        .isFalse();
            }
        }
    }

    @Test
    void onlyTheFirst72BytesCount() {
        byte[] seventyTwo = new byte[72];
        Arrays.fill(seventyTwo, (byte) 'p');
        String hash = OpenBSDBCrypt.generate("2b", seventyTwo, new byte[16], 4);
        byte[] longer = Arrays.copyOf(seventyTwo, 128);
        longer[100] = 'x';
        assertThat(BCrypt.verify(longer, hash)).isTrue();
        assertThat(BCrypt.verify(Arrays.copyOf(seventyTwo, 71), hash)).isFalse();
    }

    @Test
    void costAndMalformedHashes() {
        String good = "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.";
        assertThat(BCrypt.supports(good)).isTrue();
        assertThat(BCrypt.cost(good)).isEqualTo(6);
        assertThat(BCrypt.cost("$6$salt$hash")).isEqualTo(-1);
        assertThat(BCrypt.supports("$2x$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."))
                .as("$2x$: the old sign-extension variant")
                .isFalse();
        assertThat(BCrypt.verify(new byte[0], good.substring(0, good.length() - 1)))
                .isFalse();
        assertThat(BCrypt.verify(new byte[0], "$2a$03" + good.substring(6)))
                .as("cost below 4")
                .isFalse();
        assertThat(BCrypt.verify(new byte[0], "$2a$32" + good.substring(6)))
                .as("cost above 31")
                .isFalse();
        assertThat(BCrypt.decode("!!", 1)).isNull();
        assertThat(BCrypt.decode("....", 2)).as("too long").isNull();
        assertThat(BCrypt.decode("..", 2)).as("too short").isNull();
    }

    @Test
    void throughPasswordCheck() {
        byte[] password = utf8("arctangent");
        String hash = OpenBSDBCrypt.generate("2y", password, new byte[16], 5);
        assertThat(PasswordCheck.verify("Crypt-Password", hash, password)).isTrue();
        assertThat(PasswordCheck.verify("Crypt-Password", hash, utf8("arctangenT")))
                .isFalse();
        assertThat(PasswordCheck.isSlow("Crypt-Password", hash)).isTrue();
    }
}
