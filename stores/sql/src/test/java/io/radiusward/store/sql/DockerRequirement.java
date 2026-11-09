/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.sql;

import org.junit.jupiter.api.Assumptions;

/**
 * Tests that need Docker: skipped where Docker is missing (a contributor's laptop), a failure where it is
 * required ({@code -Dradiusward.require.docker=true}, set by CI), so they can never silently not run there.
 */
final class DockerRequirement {

    private DockerRequirement() {}

    static void check(boolean dockerAvailable, boolean required) {
        if (dockerAvailable) {
            return;
        }
        if (required) {
            throw new IllegalStateException("Docker is required (radiusward.require.docker=true) but not available");
        }
        Assumptions.abort("Docker not available: tests skipped");
    }
}
