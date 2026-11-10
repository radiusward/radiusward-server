/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.Config;
import io.radiusward.common.config.ConfigException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TotpTest {

    /** RFC 6238 appendix B, SHA-1: the ASCII seed "12345678901234567890". */
    static final byte[] SEED = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    void theRfcVectors() {
        long[][] vectors = {
            {59, 94287082},
            {1111111109, 7081804},
            {1111111111, 14050471},
            {1234567890, 89005924},
            {2000000000, 69279037},
            {20000000000L, 65353130}
        };
        for (long[] v : vectors) {
            assertThat(Totp.code(SEED, v[0] / 30, 8)).isEqualTo(String.format("%08d", v[1]));
            assertThat(Totp.code(SEED, v[0] / 30, 6)).isEqualTo(String.format("%06d", v[1] % 1_000_000));
        }
    }

    @Test
    void matchingWithinTheWindow() {
        Totp totp = Totp.DEFAULT;
        long t = 1111111111;
        assertThat(totp.match(SEED, "050471", t)).isEqualTo(t / 30);
        assertThat(totp.match(SEED, Totp.code(SEED, t / 30 - 1, 6), t))
                .as("a step behind")
                .isEqualTo(t / 30 - 1);
        assertThat(totp.match(SEED, Totp.code(SEED, t / 30 + 1, 6), t)).isEqualTo(t / 30 + 1);
        assertThat(totp.match(SEED, Totp.code(SEED, t / 30 - 2, 6), t))
                .as("outside")
                .isEqualTo(-1);
        assertThat(totp.match(SEED, "05047", t)).isEqualTo(-1);
        assertThat(totp.match(SEED, "05047a", t)).isEqualTo(-1);
        Totp strict = new Totp(false, 8, 0, Duration.ofSeconds(30), Duration.ofMinutes(1), "x");
        assertThat(strict.match(SEED, "14050471", t)).isEqualTo(t / 30);
        assertThat(strict.match(SEED, Totp.code(SEED, t / 30 - 1, 8), t)).isEqualTo(-1);
    }

    @Test
    void base32() {
        assertThat(Totp.base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")).isEqualTo(SEED);
        assertThat(Totp.base32("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")).isEqualTo(SEED);
        assertThat(Totp.base32("GEZDGNBVGY3TQOJQ====")).hasSize(10);
        assertThat(Totp.base32("GEZDGNBV")).as("too short").isNull();
        assertThat(Totp.base32("GEZDGNBVGY3TQOJ1")).as("1 is not base32").isNull();
    }

    @Test
    void configuration() {
        assertThat(Totp.from(Config.of(Map.of()))).isEqualTo(Totp.DEFAULT);
        Totp t = Totp.from(Config.of(Map.of(
                "auth.totp.mode", "append",
                "auth.totp.digits", "8",
                "auth.totp.window", "2",
                "auth.totp.timeout", "2m",
                "auth.totp.prompt", "Code?")));
        assertThat(t).isEqualTo(new Totp(true, 8, 2, Duration.ofSeconds(30), Duration.ofMinutes(2), "Code?"));
        for (Map<String, String> bad : java.util.List.of(
                Map.of("auth.totp.mode", "sms"), Map.of("auth.totp.digits", "7"), Map.of("auth.totp.window", "11"))) {
            assertThatThrownBy(() -> Totp.from(Config.of(bad))).isInstanceOf(ConfigException.class);
        }
    }
}
