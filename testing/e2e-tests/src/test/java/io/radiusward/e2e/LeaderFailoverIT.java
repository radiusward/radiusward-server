/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.protocol.SessionStatus;
import io.radiusward.tools.admin.AdminClient;
import io.radiusward.tools.radclient.LoadGenerator;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** kill -9 of the leader under load: every acknowledged event is in the replicated state, none twice. */
class LeaderFailoverIT extends E2eTestBase {

    @Test
    void killLeaderUnderLoad() throws Exception {
        Path acks = dir.resolve("acks.csv");
        LoadGenerator load = new LoadGenerator(
                new LoadGenerator.Settings(
                        List.of(
                                new InetSocketAddress("127.0.0.1", cluster.radiusPort("gateway-a")),
                                new InetSocketAddress("127.0.0.1", cluster.radiusPort("gateway-b"))),
                        Nas.SECRET,
                        10,
                        1000,
                        2000,
                        Duration.ofSeconds(25),
                        Duration.ofSeconds(5),
                        Duration.ofSeconds(3),
                        4,
                        true,
                        true,
                        acks),
                new PrintStream(System.out));
        LoadGenerator.Result[] result = new LoadGenerator.Result[1];
        Thread runner = new Thread(() -> {
            try {
                result[0] = load.run();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        runner.start();
        Thread.sleep(10_000);
        String leader = cluster.awaitLeader();
        cluster.kill(leader);
        runner.join();

        assertThat(result[0].failed())
                .as("every event acknowledged despite the failover")
                .isZero();
        // Phase 2 target: the failover finishes below the 3 s client timeout, so nothing is retransmitted
        assertThat(result[0].retransmissions())
                .as("requests needing a second attempt")
                .isZero();
        assertThat(result[0].maxMicros()).as("worst ACK latency").isLessThan(3_000_000);
        cluster.awaitConverged();

        // the last acknowledged event of every session must be what the cluster holds
        Map<String, long[]> last = new HashMap<>();
        for (String line :
                Files.readAllLines(acks).subList(1, Files.readAllLines(acks).size())) {
            String[] f = line.split(",");
            if (f[3].equals("1")) {
                long time = Long.parseLong(f[2]);
                long[] previous = last.get(f[0]);
                if (previous == null || time >= previous[1]) {
                    last.put(f[0], new long[] {Long.parseLong(f[1]), time});
                }
            }
        }
        try (AdminClient admin = cluster.admin()) {
            AdminClient.State state = admin.state();
            assertThat(state.stopped()).isEqualTo(last.size());
            assertThat(state.active()).isZero();
            for (Map.Entry<String, long[]> e : last.entrySet()) {
                long[] key = Nas.sessionKey(e.getKey());
                AdminClient.Session s = admin.session(key[0], key[1]);
                assertThat(s.status()).as(e.getKey()).isEqualTo(SessionStatus.STOPPED);
                assertThat(s.sessionTime()).as(e.getKey()).isEqualTo(e.getValue()[1]);
            }
        }
        cluster.start(leader);
        cluster.awaitReady(leader);
        cluster.awaitConverged();
    }
}
