/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TeapTlvTest {

    @Test
    void aTlvIsItsTypeWithTheMandatoryBitItsLengthAndItsValue() {
        byte[] tlv = TeapTlv.encode(TeapTlv.MANDATORY | TeapTlv.RESULT, new byte[] {0, TeapTlv.SUCCESS});
        assertThat(tlv).containsExactly(0x80, TeapTlv.RESULT, 0, 2, 0, TeapTlv.SUCCESS);
        assertThat(TeapTlv.encode(TeapTlv.AUTHORITY_ID, new byte[300])).startsWith(0, 1, 1, 44);
        assertThat(TeapTlv.MSK_MAC_AT + TeapKeys.MAC_LENGTH).isEqualTo(TeapTlv.BINDING_LENGTH);
    }
}
