/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SinkProviderTest {

    @Test
    void aSinkProviderInCodeReturnsWhatItsFactorySupplies() {
        AccountingSink sink = new AccountingSink() {
            @Override
            public void open(SinkContext context) {}

            @Override
            public CheckpointStyle checkpointStyle() {
                return CheckpointStyle.IDEMPOTENT_REPLAY;
            }

            @Override
            public long storedPosition() {
                return -1;
            }

            @Override
            public void write(Batch batch) {}

            @Override
            public void close() {}
        };
        SinkProvider provider = SinkProvider.of("mine", () -> sink);
        assertThat(provider.type()).isEqualTo("mine");
        assertThat(provider.create()).isSameAs(sink);
        assertThatThrownBy(() -> SinkProvider.of("none", () -> null).create())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("none");
    }
}
