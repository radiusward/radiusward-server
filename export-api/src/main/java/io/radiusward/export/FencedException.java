/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

/** A sink refused a write because an exporter with a newer lease epoch already wrote to it. */
public final class FencedException extends Exception {

    public FencedException(String message) {
        super(message);
    }
}
