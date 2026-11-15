/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void stringsAreQuotedAndEscaped() {
        StringBuilder out = new StringBuilder();
        Json.quote(out, "a\"b\\c\nd\re\tf\u0001g é");
        assertThat(out).hasToString("\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g é\"");
    }
}
