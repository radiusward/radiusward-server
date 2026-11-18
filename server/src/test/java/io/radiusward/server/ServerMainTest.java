/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.common.config.ConfigException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.agrona.concurrent.ShutdownSignalBarrier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code radiusward server} command lines that never get as far as starting the server. */
class ServerMainTest {

    @TempDir
    Path dir;

    private String statelessTickets;
    private final AtomicBoolean exited = new AtomicBoolean();
    private final AtomicBoolean barrierTaken = new AtomicBoolean();

    @BeforeEach
    void rememberTicketSetting() {
        statelessTickets = System.getProperty(TlsCredentials.STATELESS_TICKETS);
    }

    /** The command sets the TLS ticket property for the whole JVM; other tests here expect the JDK's default. */
    @AfterEach
    void restoreTicketSetting() {
        if (statelessTickets == null) {
            System.clearProperty(TlsCredentials.STATELESS_TICKETS);
        } else {
            System.setProperty(TlsCredentials.STATELESS_TICKETS, statelessTickets);
        }
    }

    private void run(String... args) {
        ServerMain.run(
                args,
                () -> {
                    barrierTaken.set(true);
                    return new ShutdownSignalBarrier();
                },
                () -> exited.set(true));
    }

    @Test
    void withoutAConfigFileItPrintsTheUsage() {
        assertThatThrownBy(this::run)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("usage: server --config <file.properties> [--config ...]");
        assertThatThrownBy(() -> run("--config"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("usage: server --config");
        assertThatThrownBy(() -> run("server.properties"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("usage: server --config");
        assertThat(barrierTaken).as("nothing started").isFalse();
        assertThat(exited).as("nothing to stop").isFalse();
        assertThatThrownBy(() -> ServerMain.main(new String[] {"--help"}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("usage: server --config");
    }

    @Test
    void aFileThatCannotBeReadStopsItBeforeAnythingStarts() {
        Path missing = dir.resolve("missing.properties");
        assertThatThrownBy(() -> run("--config", missing.toString()))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("cannot read configuration file " + missing);
        assertThat(barrierTaken).isFalse();
        assertThat(exited).isFalse();
    }

    @Test
    void anInvalidSettingStopsItBeforeAnythingStarts() throws Exception {
        Path file = java.nio.file.Files.writeString(dir.resolve("server.properties"), "server.threading=sometimes\n");
        assertThatThrownBy(() -> run("--config", file.toString()))
                .isInstanceOf(ConfigException.class)
                .hasMessageContaining("server.threading");
        assertThat(barrierTaken).isFalse();
        assertThat(exited).isFalse();
    }

    @Test
    void noDrainWithoutADuration() {
        // returns before it touches the server: none is needed
        ServerMain.drain(null, Duration.ZERO);
        ServerMain.drain(null, Duration.ofSeconds(-1));
    }
}
