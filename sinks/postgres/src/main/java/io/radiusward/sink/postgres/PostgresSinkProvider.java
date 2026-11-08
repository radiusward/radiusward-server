/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.postgres;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.SinkProvider;

/** {@code sink.<name>.type = postgres}. */
public final class PostgresSinkProvider implements SinkProvider {

    @Override
    public String type() {
        return "postgres";
    }

    @Override
    public AccountingSink create() {
        return new PostgresSink();
    }
}
