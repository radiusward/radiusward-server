/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.exporter.SinkConfig;
import io.radiusward.protocol.SessionStatus;
import io.radiusward.tools.admin.AdminClient;
import io.radiusward.tools.radclient.LoadGenerator;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Three members exporting to one PostgreSQL, sessions and history: the exporting member is stopped under load,
 * the lease moves with a new epoch, and afterwards every applied event is in {@code accounting_event} exactly
 * once and every session equals the replicated state. Skipped without Docker (fails in CI).
 */
class PostgresExportIT {

    private static PostgreSQLContainer postgres;

    @TempDir
    Path dir;

    @BeforeAll
    static void startPostgres() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        long deadline = System.nanoTime() + 30_000_000_000L; // Colima forwards the port shortly after start
        while (true) {
            try (Connection c = connect()) {
                if (c.isValid(5)) {
                    return;
                }
            } catch (SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw e;
                }
                Thread.sleep(250);
            }
        }
    }

    @AfterAll
    static void stopPostgres() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
    }

    @Test
    void everyAppliedEventOnceAcrossALeaseHandover() throws Exception {
        try (LocalCluster cluster = LocalCluster.start(
                dir.toFile(),
                3,
                2,
                LocalCluster.freePortBase(3),
                new int[2],
                Duration.ZERO,
                id -> new ExportConfig(
                        List.of(new SinkConfig(
                                "pg",
                                "postgres",
                                true,
                                0,
                                Duration.ofHours(4).toMillis(),
                                false,
                                5000,
                                200,
                                2000,
                                Map.of(
                                        "url", postgres.getJdbcUrl(),
                                        "user", postgres.getUsername(),
                                        "password", postgres.getPassword(),
                                        "mode", "sessions+events",
                                        "radacct.view", "true"))),
                        null,
                        null))) {
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();
            Path ackLog = dir.resolve("acks.csv");
            CompletableFuture<LoadGenerator.Result> load =
                    CompletableFuture.supplyAsync(() -> load(cluster, Duration.ofSeconds(15), ackLog));
            Thread.sleep(6_000);
            int exporting = awaitExporter(cluster, -1);
            cluster.stopNode(exporting);
            int next = awaitExporter(cluster, exporting);
            LoadGenerator.Result result = load.join();
            assertThat(result.failed()).isZero();
            cluster.startNode(exporting);
            cluster.awaitLeader();
            cluster.awaitConverged();
            ClusterNode node = cluster.node(next);
            LocalCluster.await(Duration.ofSeconds(60), "export caught up", () -> caughtUp(node));

            long events = count("SELECT count(*) FROM accounting_event");
            long distinct = count("SELECT count(DISTINCT event_id) FROM accounting_event");
            long epoch = count("SELECT epoch FROM sink_checkpoint WHERE sink = 'pg'");
            System.out.printf(
                    "postgres export: moved from member %d to %d (epoch %d), %d events (%d distinct), %d sessions; %s%n",
                    exporting,
                    next,
                    epoch,
                    events,
                    distinct,
                    count("SELECT count(*) FROM accounting_session"),
                    node.stateJson().replaceAll(".*\"export\":", ""));
            assertThat(epoch).as("the lease moved").isGreaterThanOrEqualTo(2);
            assertThat(events).as("no duplicates").isEqualTo(distinct);
            // history keeps applied and stale events (stale: an Interim older than the session's progress)
            assertThat(count("SELECT count(*) FROM accounting_event WHERE outcome = 1"))
                    .as("every applied event")
                    .isEqualTo(node.stats().applied());
            assertThat(count("SELECT count(*) FROM accounting_event WHERE outcome = 2"))
                    .as("stale events")
                    .isEqualTo(node.stats().stale());
            assertThat(count("SELECT count(*) FROM radacct WHERE acctstoptime IS NOT NULL"))
                    .isEqualTo(count("SELECT count(*) FROM accounting_session"));

            try (AdminClient admin = cluster.admin();
                    Connection c = connect();
                    Statement st = c.createStatement();
                    ResultSet rs =
                            st.executeQuery("SELECT acct_session_id, state, session_seconds FROM accounting_session")) {
                AdminClient.State state = admin.state();
                long sessions = 0;
                while (rs.next()) {
                    sessions++;
                    long[] key = LocalClusterIT.sessionKey(rs.getString(1));
                    AdminClient.Session replicated = admin.session(key[0], key[1]);
                    assertThat(rs.getInt(2) == 2)
                            .as(rs.getString(1))
                            .isEqualTo(replicated.status() == SessionStatus.STOPPED);
                    assertThat(rs.getLong(3)).as(rs.getString(1)).isEqualTo(replicated.sessionTime());
                }
                assertThat(sessions).isEqualTo(state.active() + state.stopped());
            }

            // the admin tools: verify-export against the ack log and the cluster, sinks, resync
            try (AdminClient admin = cluster.admin();
                    Connection c = connect()) {
                io.radiusward.tools.admin.AckVerifier.Report report =
                        io.radiusward.tools.admin.ExportVerifier.verify(ackLog, LocalCluster.NAS_ID, c, admin);
                assertThat(report.lost()).as("verify-export").isEmpty();
                assertThat(report.sessions()).isEqualTo(3000);

                AdminClient.SinkInfo before = admin.sinks().sinks().get(0);
                assertThat(before.name()).isEqualTo("pg");
                assertThat(before.owner()).isEqualTo(next);
                assertThat(before.epoch()).isEqualTo(epoch);

                admin.resync("pg", 0); // export everything again: idempotent, nothing may change
                LocalCluster.await(Duration.ofSeconds(60), "resync re-exported", () -> {
                    AdminClient.SinkInfo s = admin.sinks().sinks().get(0);
                    return !s.resyncPending() && s.checkpoint() >= node.stats().lastPosition();
                });
                assertThat(admin.sinks().sinks().get(0).epoch()).isGreaterThan(epoch);
            }
            assertThat(count("SELECT count(*) FROM accounting_event"))
                    .as("after resync")
                    .isEqualTo(events);
            assertThat(count("SELECT count(DISTINCT event_id) FROM accounting_event"))
                    .isEqualTo(events);
        }
    }

    private static long count(String sql) throws SQLException {
        try (Connection c = connect();
                Statement st = c.createStatement();
                ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static boolean caughtUp(ClusterNode node) {
        Matcher checkpoint = Pattern.compile("\"clusterCheckpoint\":(\\d+)").matcher(node.stateJson());
        return checkpoint.find()
                && Long.parseLong(checkpoint.group(1)) >= node.stats().lastPosition();
    }

    private static int awaitExporter(LocalCluster cluster, int not) {
        int[] found = {-1};
        LocalCluster.await(Duration.ofSeconds(30), "a member exports", () -> {
            for (int i = 0; i < 3; i++) {
                ClusterNode n = cluster.node(i);
                if (i != not && n != null && n.stateJson().contains("\"exporting\":true")) {
                    found[0] = i;
                    return true;
                }
            }
            return false;
        });
        return found[0];
    }

    private static LoadGenerator.Result load(LocalCluster cluster, Duration duration, Path ackLog) {
        try {
            return new LoadGenerator(
                            new LoadGenerator.Settings(
                                    List.of(
                                            new InetSocketAddress(
                                                    "127.0.0.1",
                                                    cluster.gateway(0).radiusPort()),
                                            new InetSocketAddress(
                                                    "127.0.0.1",
                                                    cluster.gateway(1).radiusPort())),
                                    LocalClusterIT.SECRET,
                                    10,
                                    3000,
                                    3000,
                                    duration,
                                    Duration.ofSeconds(1),
                                    Duration.ofSeconds(3),
                                    4,
                                    true,
                                    true,
                                    ackLog),
                            new PrintStream(System.out))
                    .run();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
