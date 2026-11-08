/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.radclient;

/** Bad command line input; reported without a stack trace. */
final class UsageException extends RuntimeException {
    UsageException(String message) {
        super(message);
    }
}
