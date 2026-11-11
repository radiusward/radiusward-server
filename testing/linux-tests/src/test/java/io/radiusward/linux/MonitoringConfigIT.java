/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/** The shipped alert rules and Prometheus configuration pass {@code promtool} of the image compose uses. */
@Epic("Operations")
@Feature("Alert rules")
class MonitoringConfigIT {

    private static final Path MONITORING =
            ContainerCluster.COMPOSE_DIR.resolve("../monitoring").normalize();

    private static String promtool(String... args) {
        try (GenericContainer<?> c = new GenericContainer<>(DockerImageName.parse("prom/prometheus:v3.16.0"))
                .withCopyFileToContainer(
                        MountableFile.forHostPath(MONITORING.resolve("alerts.yml")), "/etc/prometheus/alerts.yml")
                .withCopyFileToContainer(
                        MountableFile.forHostPath(MONITORING.resolve("prometheus.yml")),
                        "/etc/prometheus/prometheus.yml")
                .withCreateContainerCmdModifier(cmd -> cmd.withEntrypoint("promtool"))
                .withCommand(args)
                .withStartupCheckStrategy(new OneShotStartupCheckStrategy())) {
            c.start(); // fails unless promtool exits with 0
            return c.getLogs();
        }
    }

    @Test
    void alertRulesAndScrapeConfigAreValid() {
        assertThat(promtool("check", "rules", "/etc/prometheus/alerts.yml")).contains("SUCCESS: 16 rules found");
        assertThat(promtool("check", "config", "/etc/prometheus/prometheus.yml"))
                .contains("SUCCESS");
    }
}
