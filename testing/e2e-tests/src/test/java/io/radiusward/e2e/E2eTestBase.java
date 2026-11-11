/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import io.radiusward.testing.Reports;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.extension.TestWatcher;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;

/** Starts a fresh process cluster per test and tears it down afterwards. */
abstract class E2eTestBase {

    @TempDir(cleanup = CleanupMode.ON_SUCCESS) // keep process logs of failed tests
    Path dir;

    ProcessCluster cluster;
    Nas nas;

    /** The end of every process log, attached to a failed test's report (ADR 0064). */
    @RegisterExtension
    final TestWatcher processLogs = new TestWatcher() {
        @Override
        public void testFailed(ExtensionContext context, Throwable cause) {
            if (cluster != null) {
                for (String name : cluster.names()) {
                    Reports.attach(name + ".log", cluster.logTail(name));
                }
            }
        }
    };

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
