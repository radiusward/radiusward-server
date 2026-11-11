/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.tools.admin.AdminClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Every vendor fixture through a gateway: acknowledged and in the replicated state. */
@Epic("Accounting")
@Feature("Vendor fixtures")
class VendorFixturesIT extends E2eTestBase {

    @Test
    void allFixtures() throws Exception {
        List<Path> fixtures;
        try (Stream<Path> walk = Files.walk(Path.of("../../radius-codec/src/test/resources/fixtures"))) {
            fixtures = walk.filter(p -> p.toString().endsWith(".fixture"))
                    // per vendor in the order a NAS sends them: the timestamps are fixed and old, so an Interim
                    // before its Start would be too old to create the session
                    .sorted(java.util.Comparator.comparing(
                                    (Path p) -> p.getParent().toString())
                            .thenComparing(p -> List.of("start.fixture", "interim.fixture", "stop.fixture")
                                    .indexOf(p.getFileName().toString())))
                    .toList();
        }
        for (Path fixture : fixtures) {
            for (String line : Files.readAllLines(fixture)) {
                if (line.startsWith("packet:")) {
                    nas.ack(
                            cluster.radiusPort("gateway-b"),
                            HexFormat.of().parseHex(line.substring(7).trim()));
                }
            }
        }
        cluster.awaitConverged();
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.applied()).isEqualTo(fixtures.size());
            assertThat(state.stopped()).isEqualTo(fixtures.size() / 3);
        }
    }
}
