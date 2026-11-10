/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** MILENAGE against the 3GPP test sets (TS 35.207 §4, TS 35.208 §4) and GSM-MILENAGE (TS 55.205). */
class MilenageTest {

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replace(" ", ""));
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    @Test
    void testSet1() {
        byte[] k = hex("465b5ce8 b199b49f aa5f0a2e e238a6bc");
        byte[] rand = hex("23553cbe 9637a89d 218ae64d ae47bf35");
        byte[] sqn = hex("ff9bb4d0 b607");
        byte[] amf = hex("b9b9");
        byte[] opc = Milenage.opc(k, hex("cdc202d5 123e20f6 2b6d676a c72cb318"));
        assertThat(hex(opc)).isEqualTo("cd63cb71954a9f4e48a5994e37a02baf");
        Milenage m = new Milenage(k, opc);
        byte[] f1 = m.f1(rand, sqn, amf);
        assertThat(hex(f1)).as("f1 ‖ f1*").isEqualTo("4a9ffac354dfafb3" + "01cfaf9ec4e871e9");
        Milenage.Quintet q = m.f2345(rand);
        assertThat(hex(q.res())).as("f2").isEqualTo("a54211d5e3ba50bf");
        assertThat(hex(q.ck())).as("f3").isEqualTo("b40ba9a3c58b2a05bbf0d987b21bf8cb");
        assertThat(hex(q.ik())).as("f4").isEqualTo("f769bcd751044604127672711c6d3441");
        assertThat(hex(q.ak())).as("f5").isEqualTo("aa689c648370");
        assertThat(hex(q.akStar())).as("f5*").isEqualTo("451e8beca43b");

        Milenage.Triplet t = m.gsm(rand);
        assertThat(hex(t.sres())).as("GSM-MILENAGE SRES").isEqualTo("46f8416a");
        // Kc by conversion c3 (TS 33.102 §6.8.1.2) from test set 1's CK and IK:
        // CK1⊕CK2 = 0ffb70247790d2ce, IK1⊕IK2 = e51fcea64d697245
        assertThat(hex(t.kc())).as("GSM-MILENAGE Kc").isEqualTo("eae4be823af9a08b");

        byte[] autn = m.autn(rand, sqn, amf);
        assertThat(hex(autn)).isEqualTo("55f328b43577" + "b9b9" + "4a9ffac354dfafb3"); // SQN ⊕ AK ‖ AMF ‖ MAC-A
    }

    @Test
    void testSet2() {
        byte[] k = hex("0396eb31 7b6d1c36 f19c1c84 cd6ffd16");
        byte[] rand = hex("c00d6031 03dcee52 c4478119 494202e8");
        byte[] opc = Milenage.opc(k, hex("ff53bade 17df5d4e 793073ce 9d7579fa"));
        assertThat(hex(opc)).isEqualTo("53c15671c60a4b731c55b4a441c0bde2");
        Milenage m = new Milenage(k, opc);
        assertThat(hex(m.f1(rand, hex("fd8eef40df7d"), hex("af17")))).isEqualTo("5df5b31807e258b0a8c016e51ef4a343");
        Milenage.Quintet q = m.f2345(rand);
        assertThat(hex(q.res())).isEqualTo("d3a628ed988620f0");
        assertThat(hex(q.ck())).isEqualTo("58c433ff7a7082acd424220f2b67c556");
        assertThat(hex(q.ik())).isEqualTo("21a8c1f929702adb3e738488b9f5c5da");
        assertThat(hex(q.ak())).isEqualTo("c47783995f72");
        assertThat(hex(q.akStar())).isEqualTo("30f1197061c1");
    }

    @Test
    void resynchronisation() {
        byte[] k = hex("465b5ce8 b199b49f aa5f0a2e e238a6bc");
        byte[] opc = hex("cd63cb71 954a9f4e 48a5994e 37a02baf");
        byte[] rand = hex("23553cbe 9637a89d 218ae64d ae47bf35");
        Milenage m = new Milenage(k, opc);
        byte[] sqnMs = hex("000000001234");
        // what a USIM sends: SQN_MS ⊕ AK* ‖ MAC-S (f1* with AMF zero)
        byte[] akStar = m.f2345(rand).akStar();
        byte[] auts = new byte[14];
        for (int i = 0; i < 6; i++) {
            auts[i] = (byte) (sqnMs[i] ^ akStar[i]);
        }
        System.arraycopy(m.f1(rand, sqnMs, new byte[2]), 8, auts, 6, 8);
        assertThat(m.resync(rand, auts)).isEqualTo(sqnMs);
        auts[13] ^= 1;
        assertThat(m.resync(rand, auts)).as("a forged AUTS").isNull();
        assertThat(m.resync(rand, new byte[13])).isNull();
    }

    @Test
    void badSizes() {
        assertThatThrownBy(() -> new Milenage(new byte[15], new byte[16])).isInstanceOf(IllegalArgumentException.class);
        Milenage m = new Milenage(new byte[16], new byte[16]);
        assertThatThrownBy(() -> m.f2345(new byte[15])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> m.f1(new byte[16], new byte[5], new byte[2]))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
