/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

/** How the dictionary parser treats constructs it does not understand. */
public enum ParseMode {
    /** Any unknown keyword, type, flag or unresolved reference fails the load. Used for the bundled set. */
    STRICT,
    /** Unknown constructs are skipped with a warning naming file and line. Used for operator files. */
    LENIENT
}
