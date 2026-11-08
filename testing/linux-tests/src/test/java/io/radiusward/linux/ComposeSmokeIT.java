/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The shipped {@code deploy/compose} file as an operator would use it: {@code up --wait}, one accounting
 * request through each gateway from the tools container, {@code down -v}.
 */
class ComposeSmokeIT {

    private static final String PROJECT = "radiusward-smoke";

    @Test
    void shippedComposeFileAcknowledgesAccounting() throws Exception {
        Result up = compose("up", "-d", "--wait", "--wait-timeout", "120");
        assertThat(up.exit()).as("compose up --wait\n" + up.output()).isZero();
        for (String gateway : List.of("gateway-a:1813", "gateway-b:1813")) {
            Result acct = compose(
                    "run",
                    "--rm",
                    "tools",
                    "acct",
                    "--server",
                    gateway,
                    "--secret",
                    ContainerCluster.SECRET,
                    "--status",
                    "start",
                    "--session-id",
                    "smoke-" + gateway.charAt(8));
            assertThat(acct.exit())
                    .as("acct via " + gateway + "\n" + acct.output())
                    .isZero();
        }
        Result metrics = compose(
                "run", "--rm", "--entrypoint", "radiusward", "tools", "probe", "http://172.28.0.10:9090/metrics");
        assertThat(metrics.exit()).as("/metrics\n" + metrics.output()).isZero();
        assertThat(metrics.output())
                .contains("radiusward_accounting_events_total")
                .contains("radiusward_jvm_threads");
    }

    @AfterEach
    void down() throws Exception {
        compose("down", "-v", "--remove-orphans");
    }

    private record Result(int exit, String output) {}

    private static Result compose(String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(composeCommand());
        command.addAll(List.of(
                "-p",
                PROJECT,
                "-f",
                ContainerCluster.COMPOSE_DIR.resolve("compose.yaml").toString()));
        command.addAll(List.of(args));
        ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
        pb.environment().put("RADIUSWARD_IMAGE", ContainerCluster.IMAGE);
        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(5, TimeUnit.MINUTES)) {
            p.destroyForcibly();
        }
        System.out.println(String.join(" ", command) + "\n" + output);
        return new Result(p.exitValue(), output);
    }

    /** {@code docker compose} (plugin) where available, else the standalone {@code docker-compose}. */
    private static List<String> composeCommand() throws InterruptedException {
        try {
            Process p = new ProcessBuilder("docker", "compose", "version")
                    .redirectErrorStream(true)
                    .start();
            p.getInputStream().readAllBytes();
            if (p.waitFor() == 0) {
                return List.of("docker", "compose");
            }
        } catch (IOException e) {
            // no docker CLI plugin
        }
        return List.of("docker-compose");
    }
}
