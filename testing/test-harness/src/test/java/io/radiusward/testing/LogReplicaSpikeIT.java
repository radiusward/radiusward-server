/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.aeron.Aeron;
import io.aeron.archive.client.AeronArchive;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.qameta.allure.Link;
import io.radiusward.cluster.node.ClusterNode;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.cluster.service.Outcomes;
import io.radiusward.exporter.ClusterLogReader;
import io.radiusward.exporter.StateMachineReplica;
import io.radiusward.tools.radclient.LoadGenerator;
import java.io.File;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * P3.1 spike: the exporter reads a member's committed log from its local archive and replays it through a
 * second state machine; the replica must end with the cluster's digest — from a snapshot and from position 0,
 * across a leader failover, on every member.
 */
@Epic("Export")
@Feature("Log replica")
@Link(name = "ADR 0017", url = "https://github.com/radiusward/radiusward-server/blob/main/docs/adr/0017-exporter.md")
class LogReplicaSpikeIT {

    @TempDir
    Path dir;

    @Test
    void replicaMatchesTheClusterOnEveryMember() throws Exception {
        try (LocalCluster cluster = LocalCluster.start(dir.toFile(), 3, 2)) {
            cluster.awaitLeader();
            cluster.awaitGatewaysConnected();
            load(cluster, 4000, Duration.ofSeconds(8), 0);
            ClusterNode leader = cluster.awaitLeader();
            assertThat(leader.requestSnapshot()).isTrue();
            LocalCluster.await(
                    Duration.ofSeconds(30), "snapshot", () -> leader.stats().snapshots() >= 1);

            int killed = leader.config().nodeId();
            ClusterNode follower = cluster.node((killed + 1) % 3);
            LiveTail tail = new LiveTail(follower);
            Thread tailing = new Thread(tail, "live-tail");
            tailing.start();
            CompletableFuture<LoadGenerator.Result> second =
                    CompletableFuture.supplyAsync(() -> load(cluster, 4000, Duration.ofSeconds(10), 100_000));
            Thread.sleep(4_000);
            cluster.stopNode(killed);
            second.join();
            cluster.startNode(killed);
            cluster.awaitLeader();
            cluster.awaitConverged();
            tail.stop = true;
            tailing.join();
            System.out.printf(
                    "live tail on node %d through the failover: %d polls, %d replay restarts, %d past commit, "
                            + "digest %x / cluster %x%n",
                    follower.config().nodeId(),
                    tail.polls,
                    tail.reopens,
                    tail.pastCommit,
                    tail.digest,
                    follower.stats().digest());
            assertThat(tail.error).isNull();
            assertThat(tail.pastCommit).as("reads beyond the commit position").isZero();
            assertThat(tail.digest).isEqualTo(follower.stats().digest());

            for (int id = 0; id < 3; id++) {
                ClusterNode node = cluster.node(id);
                for (boolean fromSnapshot : new boolean[] {true, false}) {
                    Replayed r = replay(node, fromSnapshot, 7_101_000 + id * 10 + (fromSnapshot ? 1 : 2));
                    System.out.printf(
                            "node %d %s: started at %d, read %d commands (%d applied) up to %d in %d ms "
                                    + "(%.0f commands/s), digest %x / cluster %x%n",
                            id,
                            fromSnapshot ? "from snapshot" : "from 0",
                            r.startPosition,
                            r.commands,
                            r.applied,
                            r.endPosition,
                            r.millis,
                            r.commands * 1000.0 / Math.max(1, r.millis),
                            r.digest,
                            node.stats().digest());
                    assertThat(r.digest)
                            .as("node %d replica digest", id)
                            .isEqualTo(node.stats().digest());
                    assertThat(r.machineApplied).isEqualTo(node.stats().applied());
                }
            }
        }
    }

    /** Follows a member's log while the cluster fails over, checking the commit bound on every poll. */
    private static final class LiveTail implements Runnable {
        private final ClusterNode node;
        volatile boolean stop;
        volatile Throwable error;
        long polls;
        long pastCommit;
        long reopens;
        long digest;

        LiveTail(ClusterNode node) {
            this.node = node;
        }

        @Override
        public void run() {
            File clusterDir = new File(node.config().dataDir(), "cluster");
            try (Aeron aeron = Aeron.connect(
                            new Aeron.Context().aeronDirectoryName(node.config().aeronDir()));
                    AeronArchive archive = connect(aeron);
                    ClusterLogReader reader = new ClusterLogReader(aeron, archive, clusterDir, 7_102_001)) {
                StateMachineReplica replica =
                        StateMachineReplica.empty(node.config().serviceSettings(), null);
                reader.open(0);
                long deadline = Long.MAX_VALUE;
                while (true) {
                    reader.poll(replica, 256);
                    if (stop && deadline == Long.MAX_VALUE) {
                        deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
                    }
                    if (System.nanoTime() > deadline) {
                        throw new IllegalStateException(
                                "live tail stuck at " + reader.position() + ", commit " + reader.commitPosition());
                    }
                    polls++;
                    if (reader.position() > reader.commitPosition()) {
                        pastCommit++;
                    }
                    if (stop && reader.position() >= reader.commitPosition()) {
                        break;
                    }
                    Thread.onSpinWait();
                }
                digest = replica.machine().digest();
                reopens = reader.reopens();
            } catch (Throwable t) {
                error = t;
                t.printStackTrace();
            }
        }
    }

    private static AeronArchive connect(Aeron aeron) {
        return AeronArchive.connect(new AeronArchive.Context()
                .aeron(aeron)
                .controlRequestChannel("aeron:ipc?term-length=64k")
                .controlRequestStreamId(AeronArchive.Configuration.localControlStreamId())
                .controlResponseChannel("aeron:ipc?term-length=64k"));
    }

    private record Replayed(
            long startPosition,
            long endPosition,
            long commands,
            long applied,
            long machineApplied,
            long digest,
            long millis) {}

    private static Replayed replay(ClusterNode node, boolean fromSnapshot, int streamId) {
        File clusterDir = new File(node.config().dataDir(), "cluster");
        AccountingStateMachine.Settings settings = node.config().serviceSettings();
        long[] counts = new long[2];
        StateMachineReplica.OutcomeListener listener = (position, timestamp, outcome, applier) -> {
            counts[0]++;
            if (outcome == Outcomes.APPLIED) {
                counts[1]++;
            }
        };
        try (Aeron aeron = Aeron.connect(
                        new Aeron.Context().aeronDirectoryName(node.config().aeronDir()));
                AeronArchive archive = connect(aeron);
                ClusterLogReader reader = new ClusterLogReader(aeron, archive, clusterDir, streamId)) {
            long target = reader.commitPosition();
            long started = System.nanoTime();
            StateMachineReplica replica = fromSnapshot
                    ? StateMachineReplica.fromSnapshot(
                            aeron, archive, clusterDir, target, settings, streamId + 100, listener)
                    : StateMachineReplica.empty(settings, listener);
            long startPosition = replica.position();
            reader.open(startPosition);
            long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
            while (replica.position() < target && reader.position() < target) {
                if (reader.poll(replica, 256) == 0) {
                    assertThat(System.nanoTime())
                            .as("replay reached the commit position")
                            .isLessThan(deadline);
                    Thread.onSpinWait();
                }
                assertThat(reader.position()).isLessThanOrEqualTo(reader.commitPosition());
            }
            long millis = (System.nanoTime() - started) / 1_000_000;
            return new Replayed(
                    startPosition,
                    reader.position(),
                    counts[0],
                    counts[1],
                    replica.machine().applied(),
                    replica.machine().digest(),
                    millis);
        }
    }

    private static LoadGenerator.Result load(LocalCluster cluster, int rate, Duration duration, int firstSession) {
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
                                    rate,
                                    rate,
                                    duration,
                                    Duration.ofSeconds(1),
                                    Duration.ofSeconds(3),
                                    4,
                                    true,
                                    true,
                                    null,
                                    firstSession),
                            new PrintStream(System.out))
                    .run();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
