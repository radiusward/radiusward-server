/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The test vectors of "Unix crypt using SHA-256 and SHA-512" (U. Drepper). */
class ShaCryptTest {

    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            value = {
                "$5$saltstring|Hello world!|$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
                "$5$rounds=10000$saltstringsaltstring|Hello world!|"
                        + "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
                "$6$saltstring|Hello world!|$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTL"
                        + "iBFdcbYEdFCoEOfaS35inz1",
                "$6$rounds=10000$saltstringsaltstring|Hello world!|$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeX"
                        + "bDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
            })
    void specificationVectors(String setting, String password, String expected) {
        byte[] pw = password.getBytes(StandardCharsets.UTF_8);
        assertThat(ShaCrypt.crypt(pw, setting)).isEqualTo(expected);
        assertThat(ShaCrypt.verify(pw, expected)).isTrue();
        assertThat(ShaCrypt.verify("Hello world".getBytes(StandardCharsets.UTF_8), expected))
                .isFalse();
    }

    @ParameterizedTest
    @CsvSource({"$1$md5crypt$abc", "$2y$10$bcrypt", "plaintext", "$5$rounds=x$salt$h", "$6$rounds=5000"})
    void otherFormatsAreNotSha(String stored) {
        assertThat(ShaCrypt.verify("x".getBytes(StandardCharsets.UTF_8), stored))
                .isFalse();
    }
}
