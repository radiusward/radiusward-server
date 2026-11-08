/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.file;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.SinkProvider;

/** {@code sink.<name>.type = file}. */
public final class FileSinkProvider implements SinkProvider {

    @Override
    public String type() {
        return "file";
    }

    @Override
    public AccountingSink create() {
        return new FileSink();
    }
}
