/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.tools.admin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** The options of {@code admin}, checked before anything is connected to. */
class AdminMainTest {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(String... args) {
        return AdminMain.run(
                args,
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    @Test
    void theClusterCommandsNameWhatTheyMiss() {
        assertThat(run("activate-version", "--members", "x")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("admin: --version is required");
        assertThat(run("activate-version", "--version", "7")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(run("resync", "--members", "x", "--position", "0")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8))
                .contains("admin: --members is required")
                .contains("admin: --sink is required");
        assertThat(run("disconnect", "--user", "alice")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(run("coa", "--server", "http://127.0.0.1:1", "--user", "alice"))
                .isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8))
                .contains("admin: --server is required")
                .contains("admin: --attributes is required");
        assertThat(run("purge", "--members", "x")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("admin: unknown command purge");
        assertThat(out.size()).isZero();
    }

    @Test
    void theIdentityIsSourceIpOrNasIdentifier() {
        assertThat(run("export-schema", "--identity", "source-ip")).isEqualTo(AdminMain.EXIT_OK);
        assertThat(run("export-schema", "--identity", "nas-identifier")).isEqualTo(AdminMain.EXIT_OK);
        assertThat(err.size()).isZero();
        assertThat(run("export-schema", "--identity", "calling-station")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8))
                .contains("admin: --identity: expected source-ip or nas-identifier")
                .contains("usage: admin state");
    }

    @Test
    void withoutArgumentsTheUsageIsShown() {
        assertThat(run()).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("admin activate-version");
        assertThat(run("state", "--members")).isEqualTo(AdminMain.EXIT_USAGE);
        assertThat(err.toString(StandardCharsets.UTF_8)).contains("expected --option value, got --members");
    }
}
