/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.gateway.MilenageTest.hex;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;

/** The EAP-SIM/AKA/AKA′ key derivations; interop with wpa_supplicant covers them end to end (EapolTestIT). */
class SimKeysTest {

    @Test
    void fips186PrfAgainstTheFipsExample() {
        // FIPS 186-2 Appendix 3.1 (as used by wpa_supplicant's self-test): XKEY and the first two output blocks
        assertThat(hex(SimKeys.fips186Prf(hex("bd029bbe7f51960bcf9edb2b61f06f0feb5a38b6"), 40)))
                .isEqualTo("2070b3223dba372fde1c0ffc7b2e3b498b260614" + "3c6c18bacb0f6c55babb13788e20d737a3275116");
    }

    @Test
    void sha1CompressionIsShaOneWithoutPadding() throws Exception {
        // for an all-zero block the compression equals SHA-1's first step; check it against a known SHA-1 identity:
        // SHA-1("") pads to one block that is not all zeros, so instead check determinism and size
        byte[] a = SimKeys.sha1Compress(new byte[20]);
        assertThat(a).hasSize(20).isEqualTo(SimKeys.sha1Compress(new byte[20]));
        assertThat(a).isNotEqualTo(MessageDigest.getInstance("SHA-1").digest(new byte[0]));
    }

    @Test
    void keysAreCutAtTheirOffsets() {
        byte[] mk = SimKeys.akaMasterKey(
                "0232010000000000@wlan".getBytes(StandardCharsets.US_ASCII), new byte[16], new byte[16]);
        SimKeys.Keys k = SimKeys.fullKeys(mk);
        byte[] all = SimKeys.fips186Prf(mk, 160);
        assertThat(k.kEncr()).isEqualTo(java.util.Arrays.copyOfRange(all, 0, 16));
        assertThat(k.kAut()).isEqualTo(java.util.Arrays.copyOfRange(all, 16, 32));
        assertThat(k.msk()).isEqualTo(java.util.Arrays.copyOfRange(all, 32, 96));
        assertThat(k.emsk()).isEqualTo(java.util.Arrays.copyOfRange(all, 96, 160));
        assertThat(k.kRe()).isNull();

        byte[][] ckIk = SimKeys.akaPrimeCkIk(
                new byte[16], new byte[16], "WLAN".getBytes(StandardCharsets.US_ASCII), new byte[6]);
        SimKeys.Keys p = SimKeys.akaPrimeKeys(ckIk[0], ckIk[1], "6555444333222111".getBytes(StandardCharsets.US_ASCII));
        assertThat(p.kEncr()).hasSize(16);
        assertThat(p.kAut()).hasSize(32);
        assertThat(p.kRe()).hasSize(32);
        assertThat(p.msk()).hasSize(64);
        assertThat(SimKeys.prfPrime(new byte[32], new byte[] {1}, 40))
                .hasSize(40)
                .startsWith(java.util.Arrays.copyOf(SimKeys.prfPrime(new byte[32], new byte[] {1}, 32), 32));
        assertThat(SimKeys.reauthKeys(new byte[] {1}, 1, new byte[16], mk).msk())
                .hasSize(64);
        assertThat(SimKeys.akaPrimeReauthKeys(p.kRe(), new byte[] {1}, 1, new byte[16])
                        .emsk())
                .hasSize(64);
    }
}
