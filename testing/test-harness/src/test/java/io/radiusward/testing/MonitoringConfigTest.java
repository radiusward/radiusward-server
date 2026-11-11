/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The Grafana dashboards and Prometheus alerts of {@code deploy/monitoring} against the metrics the code exports: every
 * {@code radiusward_*} name they use is exported somewhere, and every exported metric is documented in
 * {@code docs/operations/monitoring.md}. Needs no Docker; {@code MonitoringConfigIT} runs promtool in CI.
 */
class MonitoringConfigTest {

    private static final Pattern METRIC = Pattern.compile("radiusward_[a-z0-9_]+");
    private static final Pattern EXPORTED = Pattern.compile("\"(radiusward_[a-z0-9_]+)\"");
    private static final Pattern EXPR = Pattern.compile("\"expr\": \"((?:[^\"\\\\]|\\\\.)*)\"");

    private static final Path ROOT = root();

    private static Path root() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.exists(p.resolve("mvnw"))) {
            p = p.getParent();
        }
        return p;
    }

    private static String read(Path p) {
        try {
            return Files.readString(p);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Metric names that appear as string literals in main sources: what the processes can export. */
    private static Set<String> exported() throws IOException {
        Set<String> names = new TreeSet<>();
        try (Stream<Path> files = Files.walk(ROOT)) {
            files.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> p.toString().contains("/src/main/java/"))
                    .filter(p -> !p.toString().contains("/target/"))
                    .forEach(p -> {
                        Matcher m = EXPORTED.matcher(read(p));
                        while (m.find()) {
                            names.add(m.group(1));
                        }
                    });
        }
        return names;
    }

    private static List<Path> dashboards() throws IOException {
        try (Stream<Path> files = Files.list(ROOT.resolve("deploy/monitoring/grafana/dashboards"))) {
            return files.filter(p -> p.toString().endsWith(".json")).sorted().toList();
        }
    }

    /** A histogram's {@code _bucket}, {@code _sum} and {@code _count} series name the histogram. */
    private static String family(String name, Set<String> exported) {
        for (String suffix : new String[] {"_bucket", "_sum", "_count"}) {
            if (name.endsWith(suffix) && exported.contains(name.substring(0, name.length() - suffix.length()))) {
                return name.substring(0, name.length() - suffix.length());
            }
        }
        return name;
    }

    @Test
    void dashboardsAndAlertsUseOnlyExportedMetrics() throws IOException {
        Set<String> exported = exported();
        assertThat(exported).contains("radiusward_gateway_access_requests_total", "radiusward_cluster_leader");
        Set<String> used = new TreeSet<>();
        for (Path dashboard : dashboards()) {
            Matcher expr = EXPR.matcher(read(dashboard));
            int exprs = 0;
            while (expr.find()) {
                exprs++;
                Matcher m = METRIC.matcher(expr.group(1));
                while (m.find()) {
                    used.add(family(m.group(), exported));
                }
            }
            assertThat(exprs).as(dashboard.getFileName() + " has queries").isPositive();
        }
        Matcher m = METRIC.matcher(read(ROOT.resolve("deploy/monitoring/alerts.yml")));
        while (m.find()) {
            used.add(family(m.group(), exported));
        }
        assertThat(exported).as("metrics the dashboards and alerts use").containsAll(used);
        assertThat(used)
                .as("the authentication metrics are on a dashboard")
                .contains(
                        "radiusward_gateway_access_rejects_total",
                        "radiusward_gateway_eap_total",
                        "radiusward_gateway_store_lookup_seconds",
                        "radiusward_gateway_sim_sqn_requests_total",
                        "radiusward_tls_certificate_expiry_timestamp_seconds");
    }

    @Test
    void everyExportedMetricIsDocumented() throws IOException {
        String doc = read(ROOT.resolve("docs/operations/monitoring.md"));
        Set<String> missing = new TreeSet<>();
        for (String name : exported()) {
            if (!doc.contains(name)) {
                missing.add(name);
            }
        }
        assertThat(missing)
                .as("exported but not in docs/operations/monitoring.md")
                .isEmpty();
    }

    @Test
    void dashboardsShareVariablesAndLinkToEachOther() throws IOException {
        Set<String> uids = new HashSet<>();
        Pattern uid = Pattern.compile("^  \"uid\": \"([a-z-]+)\"", Pattern.MULTILINE);
        Pattern id = Pattern.compile("^      \"id\": (\\d+)", Pattern.MULTILINE);
        for (Path dashboard : dashboards()) {
            String json = read(dashboard);
            Matcher u = uid.matcher(json);
            assertThat(u.find()).as(dashboard + " has a uid").isTrue();
            assertThat(uids.add(u.group(1))).as("uid " + u.group(1) + " once").isTrue();
            assertThat(dashboard.getFileName().toString()).isEqualTo(u.group(1) + ".json");
            assertThat(json)
                    .as(dashboard.getFileName() + ": data source, namespace and gateway variables, dashboard links")
                    .contains("\"uid\": \"${datasource}\"")
                    .contains("\"name\": \"namespace\"")
                    .contains("\"name\": \"gateway\"")
                    .contains("\"type\": \"dashboards\"")
                    .doesNotContain("\"uid\": \"prometheus\"");
            Set<String> ids = new HashSet<>();
            Matcher i = id.matcher(json);
            while (i.find()) {
                assertThat(ids.add(i.group(1)))
                        .as(dashboard.getFileName() + " panel id " + i.group(1))
                        .isTrue();
            }
        }
        assertThat(uids)
                .containsExactlyInAnyOrder(
                        "radiusward",
                        "radiusward-accounting",
                        "radiusward-auth",
                        "radiusward-transports",
                        "radiusward-resources");
    }
}
