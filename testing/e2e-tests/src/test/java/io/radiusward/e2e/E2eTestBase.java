/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

/** Starts a fresh process cluster per test and tears it down afterwards. */
abstract class E2eTestBase {

    @TempDir(cleanup = CleanupMode.ON_SUCCESS) // keep process logs of failed tests
    Path dir;

    ProcessCluster cluster;
    Nas nas;

    @BeforeEach
    void setUp() throws Exception {
        cluster = new ProcessCluster(dir);
        configure(cluster);
        cluster.startAll();
        cluster.awaitLeader();
        nas = new Nas();
    }

    /** Hook for tests that need extra configuration before start. */
    void configure(ProcessCluster cluster) throws Exception {}

    @AfterEach
    void tearDown() throws Exception {
        if (nas != null) {
            nas.close();
        }
        if (cluster != null) {
            cluster.close();
        }
    }
}
