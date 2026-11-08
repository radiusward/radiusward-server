/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.testing.AdminClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Every vendor fixture through a gateway: acknowledged and in the replicated state. */
class VendorFixturesIT extends E2eTestBase {

    @Test
    void allFixtures() throws Exception {
        List<Path> fixtures;
        try (Stream<Path> walk = Files.walk(Path.of("../../radius-codec/src/test/resources/fixtures"))) {
            fixtures =
                    walk.filter(p -> p.toString().endsWith(".fixture")).sorted().toList();
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
