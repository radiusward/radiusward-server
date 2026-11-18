/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HttpJsonTest {

    @Test
    void queryParametersAreDecodedInTheirOrder() {
        assertThat(HttpJson.query("user=alice%40corp&nas=core%201&flag&=x&empty="))
                .containsExactly(
                        java.util.Map.entry("user", "alice@corp"),
                        java.util.Map.entry("nas", "core 1"),
                        java.util.Map.entry("empty", ""));
        assertThat(HttpJson.query(null)).isEmpty();
    }

    @Test
    void jsonStringsAreQuotedAndEscaped() {
        assertThat(HttpJson.quote("say \"hi\" \\ now")).isEqualTo("\"say \\\"hi\\\" \\\\ now\"");
        assertThat(HttpJson.quote("tab\tnew\n")).isEqualTo("\"tab\\u0009new\\u000a\"");
        assertThat(HttpJson.quote(null)).isEqualTo("null");
    }
}
