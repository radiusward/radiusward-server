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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The exporter in a three-member cluster with the file sink on every member: under load, the exporting member
 * is stopped, the lease moves, and afterwards the union of all members' files holds every applied event and
 * the cluster's final state of every session.
 */
class ExporterIT {

    private static final Pattern FIELD = Pattern.compile("\"(\\w+)\":(\"[^\"]*\"|-?\\d+|null)");

    @TempDir
    Path dir;

    @Test
    void exportSurvivesALeaseHandover() throws Exception {
        Path exportDir = dir.resolve("export");
        try (LocalCluster cluster = LocalCluster.start(
                dir.toFile(),
                3,
                2,
                LocalCluster.freePortBase(3),
                new int[2],
                Duration.ZERO,
                id -> new ExportConfig(
                        List.of(
                                new SinkConfig(
                                        "archive",
                                        "file",
                                        true,
                                        0,
                                        Duration.ofHours(4).toMillis(),
                                        false,
                                        2000,
                                        100,
                                        2000,
                                        Map.of(
                                                "dir",
                                                exportDir.resolve("node-" + id).toString(),
                                                "mode",
                                                "sessions+events")),
                                // a second sink on the same log, own cursor and lease, sessions only
                                new SinkConfig(
                                        "mirror",
                                        "file",
                                        false,
                                        0,
                                        Duration.ofHours(4).toMillis(),
                                        true,
                                        500,
                                        50,
                                        2000,
                                        Map.of(
                                                "dir",
                                                dir.resolve("mirror/node-" + id).toString()))),
                        null,
                        null))) {
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();
            CompletableFuture<LoadGenerator.Result> load =
                    CompletableFuture.supplyAsync(() -> load(cluster, Duration.ofSeconds(12)));
            Thread.sleep(5_000);
            int exporting = awaitExporter(cluster, -1);
            cluster.stopNode(exporting);
            int next = awaitExporter(cluster, exporting);
            System.out.println("exporter moved from member " + exporting + " to member " + next);
            LoadGenerator.Result result = load.join();
            assertThat(result.failed()).isZero();
            cluster.startNode(exporting);
            cluster.awaitLeader();
            cluster.awaitConverged();
            ClusterNode any = cluster.node(next);
            LocalCluster.await(Duration.ofSeconds(30), "export caught up", () -> caughtUp(any));

            Export export = read(exportDir);
            Export mirror = read(dir.resolve("mirror"));
            assertThat(mirror.eventLines).as("mode sessions writes no events").isZero();
            assertThat(mirror.sessions.keySet()).isEqualTo(export.sessions.keySet());
            System.out.printf(
                    "export: %d event lines (%d distinct applied), %d sessions, %d duplicate lines across members%n",
                    export.eventLines, export.appliedEvents.size(), export.sessions.size(), export.duplicateLines);
            assertThat((long) export.appliedEvents.size())
                    .as("every applied event")
                    .isEqualTo(any.stats().applied());
            try (AdminClient admin = cluster.admin()) {
                AdminClient.State state = admin.state();
                assertThat((long) export.sessions.size()).isEqualTo(state.active() + state.stopped());
                for (Map<String, String> s : export.sessions.values()) {
                    String id = unquote(s.get("acct_session_id"));
                    long[] key = LocalClusterIT.sessionKey(id);
                    AdminClient.Session replicated = admin.session(key[0], key[1]);
                    assertThat(unquote(s.get("state")))
                            .as(id)
                            .isEqualTo(replicated.status() == SessionStatus.STOPPED ? "stopped" : "active");
                    assertThat(Long.parseLong(s.get("session_seconds"))).as(id).isEqualTo(replicated.sessionTime());
                }
            }
        }
    }

    private static boolean caughtUp(ClusterNode node) {
        String state = node.stateJson();
        Matcher checkpoint = Pattern.compile("\"clusterCheckpoint\":(\\d+)").matcher(state);
        return checkpoint.find()
                && Long.parseLong(checkpoint.group(1)) >= node.stats().lastPosition();
    }

    /** The member that exports the sink, other than {@code not}. */
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

    private static final class Export {
        final Set<String> appliedEvents = new HashSet<>();
        final Map<String, Map<String, String>> sessions = new HashMap<>();
        long eventLines;
        long duplicateLines;
    }

    private static Export read(Path exportDir) throws IOException {
        Export export = new Export();
        Set<String> seenLines = new HashSet<>();
        try (Stream<Path> files = Files.walk(exportDir)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".jsonl")).toList()) {
                for (String line : Files.readAllLines(f)) {
                    if (!seenLines.add(line)) {
                        export.duplicateLines++;
                    }
                    Map<String, String> fields = new HashMap<>();
                    Matcher m = FIELD.matcher(line);
                    while (m.find()) {
                        fields.putIfAbsent(m.group(1), m.group(2));
                    }
                    if (line.startsWith("{\"type\":\"event\"")) {
                        export.eventLines++;
                        if (fields.get("outcome").equals("\"applied\"")) {
                            export.appliedEvents.add(fields.get("event_id"));
                        }
                    } else {
                        export.sessions.merge(
                                fields.get("session_key"),
                                fields,
                                (a, b) -> Long.parseLong(a.get("version")) >= Long.parseLong(b.get("version")) ? a : b);
                    }
                }
            }
        }
        // the latest snapshot of a session may be a closure without acct_session_id; take the id from any line
        return export;
    }

    private static String unquote(String s) {
        return s == null || s.equals("null") ? null : s.substring(1, s.length() - 1);
    }

    private static LoadGenerator.Result load(LocalCluster cluster, Duration duration) {
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
                                    2000,
                                    2000,
                                    duration,
                                    Duration.ofSeconds(1),
                                    Duration.ofSeconds(3),
                                    4,
                                    true,
                                    true,
                                    null),
                            new PrintStream(System.out))
                    .run();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
