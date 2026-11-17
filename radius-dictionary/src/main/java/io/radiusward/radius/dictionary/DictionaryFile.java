/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.List;

/**
 * The dictionary file being read: where the parser is in it, its mode, and how a problem is handled there: a failure
 * in strict mode, a warning and the line skipped in lenient mode.
 */
final class DictionaryFile {

    /** A line of a dictionary file, for messages. */
    record Location(String file, int line) {
        @Override
        public String toString() {
            return file + ":" + line;
        }
    }

    final DictionarySource source;
    final ParseMode mode;
    private final List<String> warnings;
    /** {@code FLAGS internal} is in effect. */
    boolean internal;
    /** The line being parsed. */
    Location at;

    DictionaryFile(DictionarySource source, ParseMode mode, List<String> warnings) {
        this.source = source;
        this.mode = mode;
        this.warnings = warnings;
    }

    boolean strict() {
        return mode == ParseMode.STRICT;
    }

    /** Strict mode: fail. Lenient mode: record a warning and continue. */
    void problem(String message) {
        if (strict()) {
            throw new DictionaryException(at + ": " + message);
        }
        warnings.add(at + ": " + message + " (skipped)");
    }

    /** A warning at this line that never fails, even in strict mode. */
    void warn(String message) {
        warnings.add(at + ": " + message);
    }

    /** Whether the line has at least {@code min} tokens, the keyword included; a problem otherwise. */
    boolean requireTokens(String[] t, int min) {
        if (t.length < min) {
            problem(t[0] + " needs at least " + (min - 1) + " arguments");
            return false;
        }
        return true;
    }

    /** An unsigned 32-bit number (decimal or {@code 0x} hex); a problem and {@code -1} otherwise. */
    int number(String token) {
        Long value = DictionaryNumbers.parseLong(token);
        if (value == null || value < 0 || value > 0xFFFF_FFFFL) {
            problem("invalid number " + token);
            return -1;
        }
        return (int) (long) value;
    }
}
