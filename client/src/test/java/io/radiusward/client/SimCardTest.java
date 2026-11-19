/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.eap.Milenage;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class SimCardTest {

    static final byte[] KI = HexFormat.of().parseHex("465b5ce8b199b49faa5f0a2ee238a6bc");
    static final byte[] OP = HexFormat.of().parseHex("cdc202d5123e20f62b6d676ac72cb318");

    @Test
    void aCardIsAnImsiWithSixteenByteKeys() {
        assertThatThrownBy(() -> new SimCard("26201", KI, KI)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SimCard("26201100000000x", KI, KI)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SimCard("262011000000001", new byte[15], KI))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(new SimCard("262011000000001", KI, KI).imsi()).isEqualTo("262011000000001");
    }

    @Test
    void theSequenceNumberIsFortyEightBits() {
        SimCard card = new SimCard("262011000000001", KI, KI);
        assertThat(card.sqn()).isZero();
        assertThat(card.sqn((1L << 48) - 1).sqn()).isEqualTo((1L << 48) - 1);
        assertThatThrownBy(() -> card.sqn(1L << 48)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> card.sqn(-1)).isInstanceOf(IllegalArgumentException.class);
        card.accepted(42);
        assertThat(card.sqn()).isEqualTo(42);
    }

    @Test
    void withOpDerivesOpcAsTheOperatorDoes() {
        byte[] rand = new byte[16];
        Milenage expected = new Milenage(KI, Milenage.opc(KI, OP));
        assertThat(SimCard.withOp("262011000000001", KI, OP)
                        .milenage()
                        .f2345(rand)
                        .res())
                .isEqualTo(expected.f2345(rand).res());
    }

    @Test
    void simLoginsUseThePermanentIdentityOfTheirMethod() {
        SimCard card = new SimCard("262011000000001", KI, KI);
        assertThat(EapLogin.sim(card).identity()).isEqualTo("1262011000000001");
        assertThat(EapLogin.aka(card).identity()).isEqualTo("0262011000000001");
        assertThat(EapLogin.akaPrime(card)
                        .realm("wlan.mnc001.mcc262.3gppnetwork.org")
                        .identity())
                .isEqualTo("6262011000000001@wlan.mnc001.mcc262.3gppnetwork.org");
    }
}
