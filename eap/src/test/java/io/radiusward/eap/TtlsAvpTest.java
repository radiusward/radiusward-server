/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TtlsAvpTest {

    @Test
    void anIetfAvpHasNoVendorAndIsPaddedToFourBytes() {
        byte[] avp = TtlsAvp.encode(1, 0, "alice".getBytes());
        assertThat(avp).hasSize(16); // 8 header + 5 value + 3 padding
        assertThat(avp).startsWith(0, 0, 0, 1, TtlsAvp.FLAG_MANDATORY, 0, 0, 13);
        assertThat(new String(avp, 8, 5)).isEqualTo("alice");
        assertThat(avp).endsWith(0, 0, 0);
    }

    @Test
    void aVendorAvpCarriesItsVendorAndTheLengthWithoutPadding() {
        byte[] avp = TtlsAvp.encode(25, 311, new byte[] {1, 2, 3, 4});
        assertThat(avp).hasSize(16);
        assertThat(avp[4]).isEqualTo((byte) (TtlsAvp.FLAG_VENDOR | TtlsAvp.FLAG_MANDATORY));
        assertThat(avp[7]).as("length: 12 header + 4 value").isEqualTo((byte) 16);
        assertThat(avp).containsSequence(0, 0, 1, 0x37); // vendor 311
    }
}
