/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/** PEAPv0 crypto-binding: PRF+, the TLV both ways, the session key. Interop with wpa_supplicant: EapolTestIT. */
class PeapCryptoBindingTest {

    private static final byte[] TUNNEL = HexFormat.of().parseHex("00112233445566778899aabbccddeeff".repeat(4));
    private static final byte[] ISK = HexFormat.of().parseHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0".repeat(2));

    @Test
    void prfPlusChainsHmacSha1Blocks() throws Exception {
        byte[] label = "label".getBytes();
        byte[] seed = {1, 2, 3};
        byte[] out = PeapCryptoBinding.prfPlus(TUNNEL, label, seed, 45);
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(TUNNEL, "HmacSHA1"));
        mac.update(label);
        mac.update(seed);
        byte[] t1 = mac.doFinal(new byte[] {1, 0, 0});
        mac.update(t1);
        mac.update(label);
        mac.update(seed);
        byte[] t2 = mac.doFinal(new byte[] {2, 0, 0});
        assertThat(Arrays.copyOf(out, 20)).isEqualTo(t1);
        assertThat(Arrays.copyOfRange(out, 20, 40)).isEqualTo(t2);
        assertThat(out).hasSize(45);
    }

    @Test
    void aPeerAnswerWithTheSameKeysVerifies() {
        PeapCryptoBinding server = new PeapCryptoBinding(TUNNEL, ISK);
        byte[] nonce = new byte[32];
        nonce[0] = 42;
        byte[] request = server.request(nonce);
        assertThat(request).hasSize(60);
        assertThat(request[1]).isEqualTo((byte) 12);

        byte[] answer = answer(new PeapCryptoBinding(TUNNEL, ISK), nonce);
        assertThat(server.verifies(answer, nonce)).isTrue();
        byte[] unflipped = answer(new PeapCryptoBinding(TUNNEL, ISK), nonce, false);
        assertThat(server.verifies(unflipped, nonce))
                .as("wpa_supplicant echoes the nonce")
                .isTrue();
        assertThat(server.msk()).hasSize(64).isEqualTo(new PeapCryptoBinding(TUNNEL, ISK).msk());

        assertThat(server.verifies(answer(new PeapCryptoBinding(TUNNEL, new byte[32]), nonce), nonce))
                .as("another inner key: a relayed inner exchange")
                .isFalse();
        assertThat(server.verifies(request, nonce))
                .as("our own request reflected")
                .isFalse();
        byte[] other = nonce.clone();
        other[0] ^= 1;
        assertThat(server.verifies(answer(new PeapCryptoBinding(TUNNEL, ISK), other), nonce))
                .as("another nonce")
                .isFalse();
        assertThat(server.verifies(Arrays.copyOf(answer, 59), nonce)).isFalse();
    }

    @Test
    void msChapV2IskIsTheServersReceiveThenSendKey() {
        byte[] hashHash = Md4.digest(MsChap.ntHash("clientPass"));
        byte[] response = new byte[24];
        byte[] master = MsChap.masterKeyFromKey(hashHash, response);
        byte[] isk = PeapCryptoBinding.msChapV2Isk(hashHash, response);
        assertThat(Arrays.copyOf(isk, 16)).isEqualTo(MsChap.serverKey(master, false));
        assertThat(Arrays.copyOfRange(isk, 16, 32)).isEqualTo(MsChap.serverKey(master, true));
    }

    /** As a peer answers: subtype 1, the nonce with its last bit flipped, its MAC over the TLV with a zero MAC. */
    private static byte[] answer(PeapCryptoBinding peer, byte[] nonce) {
        return answer(peer, nonce, true);
    }

    private static byte[] answer(PeapCryptoBinding peer, byte[] nonce, boolean flip) {
        byte[] tlv = new byte[60];
        tlv[1] = 12;
        tlv[3] = 56;
        tlv[7] = 1;
        System.arraycopy(nonce, 0, tlv, 8, 32);
        if (flip) {
            tlv[39] ^= 1;
        }
        System.arraycopy(peer.mac(tlv), 0, tlv, 40, 20);
        return tlv;
    }
}
