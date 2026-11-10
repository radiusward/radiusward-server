/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.radius;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.SinkProvider;

/** {@code sink.<name>.type = radius}: accounting of proxied realms forwarded to their home servers (ADR 0037). */
public final class RadiusSinkProvider implements SinkProvider {

    @Override
    public String type() {
        return "radius";
    }

    @Override
    public AccountingSink create() {
        return new RadiusSink();
    }
}
