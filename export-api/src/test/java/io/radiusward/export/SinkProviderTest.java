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

    @Test
    void aSinkAsAFunctionGetsEveryBatchAndStoresNoPosition() throws Exception {
        java.util.List<Batch> got = new java.util.ArrayList<>();
        AccountingSink sink = AccountingSink.of(got::add);
        sink.open(null);
        Batch batch = new Batch("s", 1, 0, 10, 0, java.util.List.of(), java.util.List.of());
        sink.write(batch);
        assertThat(got).containsExactly(batch);
        assertThat(sink.storedPosition()).isEqualTo(-1);
        assertThat(sink.checkpointStyle()).isEqualTo(AccountingSink.CheckpointStyle.IDEMPOTENT_REPLAY);
        sink.close();
    }
}
