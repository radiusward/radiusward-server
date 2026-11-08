/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

/** Thrown when a dictionary cannot be loaded. The message names the file and line. */
public final class DictionaryException extends RuntimeException {

    public DictionaryException(String message) {
        super(message);
    }

    public DictionaryException(String message, Throwable cause) {
        super(message, cause);
    }
}
