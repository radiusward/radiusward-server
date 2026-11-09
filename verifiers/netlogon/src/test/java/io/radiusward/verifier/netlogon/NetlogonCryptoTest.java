/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class NetlogonCryptoTest {

    @Test
    void ntHashAndMd4() {
        assertThat(HexFormat.of().formatHex(NetlogonCrypto.ntHash("password")))
                .isEqualTo("8846f7eaee8fb117ad06bdd830b7586c");
    }

    @Test
    void credentialsAreAesCfb8WithAZeroIvAndReversible() {
        byte[] key = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] input = HexFormat.of().parseHex("1122334455667788");
        byte[] credential = NetlogonCrypto.credential(input, key);
        assertThat(credential).hasSize(8).isNotEqualTo(input);
        assertThat(NetlogonCrypto.aesCfb8(key, new byte[16], credential, false)).isEqualTo(input);
        assertThat(NetlogonCrypto.sessionKey(new byte[16], input, input)).hasSize(16);
    }

    @Test
    void uuidsAndTowers() {
        assertThat(HexFormat.of().formatHex(Ndr.uuidBytes(UUID.fromString("12345678-1234-abcd-ef00-01234567cffb"))))
                .isEqualTo("785634123412cdabef0001234567cffb");
        byte[] tower = EndpointMapper.tower(NetlogonClient.NETLOGON, 1, 0);
        assertThat(tower).hasSize(75);
        tower[tower.length - 11] = (byte) 0xC0; // the port floor: 49153, big-endian
        tower[tower.length - 10] = 0x01;
        assertThat(EndpointMapper.portOf(tower)).isEqualTo(49153);
    }
}
