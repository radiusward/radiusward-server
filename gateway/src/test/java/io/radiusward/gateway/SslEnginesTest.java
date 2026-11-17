/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class SslEnginesTest {

    @Test
    void aGrownBufferKeepsWhatWasWrittenAndHasRoomForMore() {
        ByteBuffer small = ByteBuffer.allocate(4);
        small.put(new byte[] {1, 2, 3});
        ByteBuffer larger = SslEngines.grow(small, 10);
        assertThat(larger.capacity()).isEqualTo(14);
        assertThat(larger.position())
                .as("left for writing after the copied bytes")
                .isEqualTo(3);
        larger.put((byte) 4);
        larger.flip();
        byte[] contents = new byte[larger.remaining()];
        larger.get(contents);
        assertThat(contents).containsExactly(1, 2, 3, 4);
    }
}
