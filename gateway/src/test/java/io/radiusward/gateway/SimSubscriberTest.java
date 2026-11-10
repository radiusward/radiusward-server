/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static io.radiusward.gateway.MilenageTest.hex;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import java.util.List;
import org.junit.jupiter.api.Test;

/** SIM keys from store check items under both naming schemes (ADR 0061), and the SIM message codec. */
class SimSubscriberTest {

    static AttributeItem item(String name, String value) {
        return new AttributeItem(name, ":=", value);
    }

    @Test
    void keysUnderEitherName() {
        SimSubscriber v4 = SimSubscriber.of(List.of(
                item("SIM-Ki", "0x465b5ce8b199b49faa5f0a2ee238a6bc"),
                item("SIM-OP", "cdc202d5123e20f62b6d676ac72cb318"),
                item("SIM-AMF", "0x8000"),
                item("SIM-SQN", "4096"),
                item("SIM-Algo-Version", "Milenage")));
        assertThat(v4.opc()).as("derived from OP").isEqualTo(hex("cd63cb71954a9f4e48a5994e37a02baf"));
        assertThat(v4.amf()).isEqualTo(hex("8000"));
        assertThat(v4.sqn()).isEqualTo(4096);
        assertThat(v4.milenage()).isTrue();

        SimSubscriber v3 = SimSubscriber.of(List.of(
                item("EAP-Sim-Ki", "465b5ce8b199b49faa5f0a2ee238a6bc"),
                item("EAP-Sim-Algo-Version", "2"),
                item("EAP-Sim-Rand1", "00000000000000000000000000000001"),
                item("EAP-Sim-SRES1", "11111111"),
                item("EAP-Sim-KC1", "2222222222222222"),
                item("EAP-Sim-Rand2", "00000000000000000000000000000002"),
                item("EAP-Sim-SRES2", "11111112"),
                item("EAP-Sim-KC2", "2222222222222223"),
                item("EAP-Sim-Rand3", "00000000000000000000000000000003"),
                item("EAP-Sim-SRES3", "11111113"),
                item("EAP-Sim-KC3", "2222222222222224"),
                item("Cleartext-Password", "ignored")));
        assertThat(v3.milenage()).as("COMP128-2 is not supported").isFalse();
        assertThat(v3.triplets()).hasSize(3);
        assertThat(v3.gsm()).as("the stored triplets serve EAP-SIM").isTrue();
        assertThat(SimSubscriber.of(List.of()).gsm()).isFalse();
        assertThat(SimSubscriber.of(List.of(item("SIM-Ki", "465b5ce8b199b49faa5f0a2ee238a6bc")))
                        .milenage())
                .as("no OPc")
                .isFalse();
    }

    @Test
    void badValuesNameTheItemButNotTheValue() {
        for (AttributeItem bad : List.of(
                item("SIM-Ki", "0x1234"),
                item("SIM-OPc", "zz"),
                item("SIM-SQN", "-1"),
                item("SIM-SQN", "281474976710656"),
                item("SIM-Algo-Version", "comp128-9"),
                item("EAP-Sim-Rand4", "00"))) {
            assertThatThrownBy(() -> SimSubscriber.of(List.of(bad)))
                    .as(bad.attribute())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith(bad.attribute())
                    .satisfies(e -> assertThat(e.getMessage()).doesNotContain(bad.value()));
        }
    }

    @Test
    void messages() {
        SimMessage.Builder b = new SimMessage.Builder(1)
                .reserved(SimMessage.AT_RAND, new byte[16])
                .uint16(SimMessage.AT_KDF, 1)
                .lengthPrefixed(SimMessage.AT_IDENTITY, new byte[] {'a', 'b', 'c'})
                .mac();
        byte[] data = b.build();
        SimMessage m = SimMessage.parse(data);
        assertThat(m.subtype()).isEqualTo(1);
        assertThat(m.get(SimMessage.AT_RAND)).hasSize(18);
        assertThat(SimMessage.lengthPrefixed(m.get(SimMessage.AT_IDENTITY))).containsExactly('a', 'b', 'c');
        assertThat(m.macOffset()).isEqualTo(b.macOffset());
        assertThat(SimMessage.parse(new byte[] {1, 0})).as("too short").isNull();
        assertThat(SimMessage.parse(new byte[] {1, 0, 0, 1, 0}))
                .as("zero length")
                .isNull();
        assertThat(SimMessage.parse(new byte[] {1, 0, 0, 1, 5, 0, 0}))
                .as("truncated")
                .isNull();
        assertThat(SimMessage.parse(new byte[] {1, 0, 0, 6, 1, 0, 0, 6, 1, 0, 0}))
                .as("twice")
                .isNull();
        assertThat(SimMessage.parse(new byte[] {1, 0, 0, (byte) 200, 1, 0, 0}).has(200))
                .as("skippable (128 and above) are kept")
                .isTrue();
        assertThat(SimMessage.lengthPrefixed(new byte[] {0, 9, 1}))
                .as("longer than the value")
                .isNull();
        assertThat(SimMessage.lengthPrefixed(null)).isNull();
    }
}
