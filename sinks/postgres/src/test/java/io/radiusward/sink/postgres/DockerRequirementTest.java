/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.sink.postgres;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.opentest4j.TestAbortedException;

class DockerRequirementTest {

    @Test
    void skipsLocallyAndFailsInCi() {
        assertThatCode(() -> DockerRequirement.check(true, true)).doesNotThrowAnyException();
        assertThatCode(() -> DockerRequirement.check(true, false)).doesNotThrowAnyException();
        assertThatThrownBy(() -> DockerRequirement.check(false, false)).isInstanceOf(TestAbortedException.class);
        assertThatThrownBy(() -> DockerRequirement.check(false, true))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("radiusward.require.docker");
    }
}
