/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * TEAP's key hierarchy and Compound MAC (ADR 0041) against the values wpa_supplicant 2.12 logged for one conversation
 * (cipher suite 0xc02c, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: PRF and MAC with SHA-384).
 */
class TeapKeysTest {

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    static final byte[] SEED = hex("05 ee c3 33 cf f8 d8 64 99 cc a4 46 fc 58 9e 7c ec cc fd c0 c9 3a 52 04 78 42 a8"
            + " 31 70 0c 90 47 7c f4 5a a0 36 2d 7c 97");
    static final byte[] IMSK =
            hex("98 98 f7 8d 4c b5 0f 5a 6a 4a 82 5c 35 b8 22 fb c9 ec 74 bf f3 a4 d8 09 d6 74 5a" + " 04 5c 54 81 19");
    static final byte[] SIMCK = hex("1f 01 ef 26 0b 98 4f 95 2d 68 56 85 11 63 d4 2f 2e 87 e0 59 83 77 fd 2f 50 83 c8"
            + " 33 70 31 e6 b2 07 fa ca aa 68 ee 75 a2");
    static final byte[] CMK = hex("1b 49 22 36 c0 a1 d3 2d 36 9d 97 4b fc 27 bb fe c9 e5 cd 0d");
    /** The Crypto-Binding TLV of that conversation, MAC fields zeroed (the start of the peer's BUFFER). */
    static final byte[] BINDING = hex("80 0c 00 4c 00 01 01 20 ee 93 c6 c7 9a d9 4e 0a e6 aa 00 73 31 b9 08 69 00 1e"
            + " 0e 14 40 2f ff e3 10 fc f6 91 ed e3 f8 7a" + " 00".repeat(40));

    static final byte[] AUTHORITY_ID_TLV = hex("00 01 00 0a 72 61 64 69 75 73 77 61 72 64");
    static final byte[] PEER_MAC = hex("32 05 24 a9 66 e2 ab 05 f0 c9 d1 f2 b7 a6 3d 45 6a 55 d1 d8");

    private final TeapKeys keys = new TeapKeys("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

    @Test
    void theInnerMethodsCompoundKeysMatchThePeers() {
        TeapKeys.Compound c = keys.next(SEED, IMSK, null);
        assertThat(c.simck()).isEqualTo(SIMCK);
        assertThat(c.cmk()).isEqualTo(CMK);
    }

    @Test
    void theCompoundMacMatchesThePeers() {
        byte[] withMacs = BINDING.clone();
        Arrays.fill(withMacs, 60, 80, (byte) 0x55); // ignored: zeroed for the computation
        assertThat(keys.compoundMac(CMK, withMacs, AUTHORITY_ID_TLV, new byte[0]))
                .isEqualTo(PEER_MAC);
    }

    @Test
    void anMskShorterThan32BytesIsPaddedAndNoKeyIsZeros() {
        TeapKeys.Compound none = keys.next(SEED, null, null);
        assertThat(keys.next(SEED, new byte[0], null).simck()).isEqualTo(none.simck());
        assertThat(keys.next(SEED, new byte[32], null).cmk()).isEqualTo(none.cmk());
        assertThat(keys.msk(SIMCK)).hasSize(64);
        TeapKeys sha256 = new TeapKeys("TLS_AES_128_GCM_SHA256");
        assertThat(sha256.next(SEED, IMSK, null).simck()).isNotEqualTo(SIMCK);
        assertThat(new TeapKeys("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
                        .compoundMac(CMK, BINDING, new byte[0], new byte[0]))
                .hasSize(20);
    }
}
