/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

/** The store cannot answer now (down, timed out, no free connection): the request is left unanswered. */
public class StoreUnavailableException extends Exception {

    public StoreUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public StoreUnavailableException(String message) {
        super(message);
    }
}
