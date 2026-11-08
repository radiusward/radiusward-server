/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

/** Registered in {@code META-INF/services/io.radiusward.export.SinkProvider}. */
public interface SinkProvider {

    /** The value of {@code sink.<name>.type}, e.g. {@code postgres}, {@code file}. */
    String type();

    AccountingSink create();
}
