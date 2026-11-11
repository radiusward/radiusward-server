/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

/**
 * Attaches the end of every container log to a failed test's report (ADR 0064). {@link ContainerCluster#close()}
 * saves the logs; this extension, registered for every test of the module (META-INF/services), reads the ones the
 * test's clusters saved. Never fails a test itself.
 */
public final class FailureLogs implements BeforeEachCallback, TestWatcher {

    private static final int LINES = 200;

    @Override
    public void beforeEach(ExtensionContext context) {
        ContainerCluster.savedLogs.clear();
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        for (Path dir : List.copyOf(ContainerCluster.savedLogs)) {
            try (Stream<Path> files = Files.list(dir)) {
                files.filter(f -> f.toString().endsWith(".log")).sorted().forEach(f -> {
                    try {
                        List<String> lines = Files.readAllLines(f);
                        Reports.attach(
                                dir.getFileName() + "/" + f.getFileName(),
                                String.join("\n", lines.subList(Math.max(0, lines.size() - LINES), lines.size())));
                    } catch (IOException | RuntimeException e) {
                        // a diagnostic must never hide the test's own result
                    }
                });
            } catch (IOException | RuntimeException e) {
                // as above
            }
        }
    }
}
