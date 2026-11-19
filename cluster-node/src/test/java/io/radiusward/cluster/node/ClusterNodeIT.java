/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import static org.assertj.core.api.Assertions.assertThat;

import io.aeron.Aeron;
import io.aeron.cluster.ClusterControl;
import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.cluster.service.AccountingStateMachine;
import io.radiusward.common.Profile;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.testing.Await;
import io.radiusward.testing.Ports;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.agrona.CloseHelper;
import org.agrona.concurrent.status.AtomicCounter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * One cluster member on its own: the scheduled snapshots, the log purge tick, the cluster's own shutdown, and a second
 * instance on the same data directory, which waits while the first one's mark files are still in use.
 */
@Epic("Cluster")
@Feature("Cluster member")
class ClusterNodeIT {

    @TempDir
    Path dir;

    private ClusterNode first;
    private ClusterNode second;
    private Aeron aeron;

    @AfterEach
    void tearDown() {
        CloseHelper.quietCloseAll(aeron, second, first);
    }

    private ClusterNodeConfig config(
            int basePort, String aeronDir, Profile profile, Duration snapshotInterval, LogPurgeConfig purge) {
        return new ClusterNodeConfig(
                0,
                List.of("localhost"),
                basePort,
                new File(dir.toFile(), "data"),
                new File(dir.toFile(), aeronDir).getPath(),
                profile,
                Duration.ofMillis(1500),
                Duration.ofMillis(500),
                Duration.ofSeconds(10),
                snapshotInterval,
                2,
                1,
                256,
                AccountingStateMachine.Settings.defaults(1000),
                Duration.ofSeconds(60),
                ExportConfig.NONE,
                purge);
    }

    /** Whether {@code thread} sleeps in ClusterNode itself (the wait between two attempts), not in a library. */
    private static boolean sleepsIn(Thread thread) {
        StackTraceElement[] stack = thread.getStackTrace();
        int i = 0;
        while (i < stack.length && stack[i].getClassName().equals(Thread.class.getName())) {
            i++;
        }
        return i > 0
                && i < stack.length
                && stack[i - 1].getMethodName().startsWith("sleep")
                && stack[i].getClassName().equals(ClusterNode.class.getName());
    }

    private static void awaitLeader(ClusterNode node) {
        Await.until(
                Duration.ofSeconds(30),
                "leader elected",
                () -> "LEADER".equals(node.stats().role()));
    }

    @Test
    void snapshotsOnScheduleAndStopsWhenTheClusterShutsDown() throws Exception {
        CountDownLatch terminated = new CountDownLatch(1);
        ClusterNodeConfig config = config(
                Ports.freePortBase(1),
                "aeron",
                Profile.LARGE, // dedicated archive thread
                Duration.ofMillis(300),
                new LogPurgeConfig(false, false, 128 << 20, Duration.ofMinutes(1)));
        first = ClusterNode.launch(config, terminated::countDown);
        awaitLeader(first);
        assertThat(first.health().up()).isTrue();
        assertThat(first.health().detail()).isEqualTo("cluster node 0 running");
        // the role turns LEADER before the election closes (LEADER_READY in between): wait for the end
        Await.until(
                Duration.ofSeconds(30),
                "election closed",
                () -> first.electionState() == io.aeron.cluster.ElectionState.CLOSED);
        Await.until(
                Duration.ofSeconds(30),
                "scheduled snapshots",
                () -> first.stats().snapshots() >= 2);

        // the purge tick, called by hand with the purge off: it works, fails without the recording log, works again
        first.purgeTick();
        assertThat(first.stateJson()).contains("\"logPurge\"");
        Path recordingLog = dir.resolve("data/cluster/" + io.aeron.cluster.RecordingLog.RECORDING_LOG_FILE_NAME);
        Path aside = dir.resolve("recording.log.aside");
        Files.move(recordingLog, aside);
        try {
            first.purgeTick(); // logged and retried next time, never thrown
        } finally {
            Files.move(aside, recordingLog, StandardCopyOption.REPLACE_EXISTING);
        }
        first.purgeTick();

        // the cluster shuts itself down (ClusterTool shutdown): the termination hook tells the process
        aeron = Aeron.connect(new Aeron.Context().aeronDirectoryName(config.aeronDir()));
        AtomicCounter toggle = ClusterControl.findControlToggle(aeron.countersReader(), 0);
        assertThat(toggle).isNotNull();
        assertThat(ClusterControl.ToggleState.SHUTDOWN.toggle(toggle)).isTrue();
        assertThat(terminated.await(30, TimeUnit.SECONDS))
                .as("termination hook")
                .isTrue();
        first.markTerminated();
        assertThat(first.health().up()).isFalse();
        assertThat(first.health().detail()).isEqualTo("terminated");
        CloseHelper.quietClose(aeron);
        aeron = null;

        first.close();
        assertThat(first.health().up()).isFalse();
        assertThat(first.electionState()).as("no election state once closed").isNull();
        first.snapshotIfLeader(); // a failed request is logged, never thrown
        first = null;
    }

    @Test
    void aSecondInstanceWaitsUntilTheFirstHasStopped() throws Exception {
        int basePort = Ports.freePortBase(1);
        LogPurgeConfig purge = new LogPurgeConfig(true, false, 128 << 20, Duration.ofMinutes(1));
        first = ClusterNode.launch(config(basePort, "aeron-1", Profile.SMALL, Duration.ZERO, purge), null);
        awaitLeader(first);
        ClusterNodeConfig again = config(basePort, "aeron-2", Profile.SMALL, Duration.ZERO, purge);

        // interrupted while it waits for the mark file: gives up with the mark file's error
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Boolean> interruptedAfter = new AtomicReference<>();
        Thread interrupted = new Thread(() -> {
            try {
                second = ClusterNode.launch(again, null);
            } catch (Throwable t) {
                failure.set(t);
                interruptedAfter.set(Thread.currentThread().isInterrupted());
            }
        });
        interrupted.start();
        // only while it waits for the next attempt: an interrupt during an attempt ends inside Aeron instead
        Await.until(Duration.ofSeconds(30), "the second instance waits for the mark file", () -> sleepsIn(interrupted));
        interrupted.interrupt();
        interrupted.join(30_000);
        assertThat(interrupted.isAlive()).isFalse();
        assertThat(failure.get())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("active mark file detected");
        assertThat(interruptedAfter.get()).as("interrupt kept").isTrue();
        assertThat(first.health().up()).as("the first one keeps running").isTrue();

        // waits and starts once the first one has stopped
        failure.set(null);
        Thread waiting = new Thread(() -> {
            try {
                second = ClusterNode.launch(again, null);
            } catch (Throwable t) {
                failure.set(t);
            }
        });
        waiting.start();
        Thread.sleep(1500);
        assertThat(waiting.isAlive()).as("still waiting").isTrue();
        first.close();
        first = null;
        waiting.join(30_000);
        assertThat(failure.get()).isNull();
        assertThat(second).isNotNull();
        awaitLeader(second);

        // closed from an interrupted thread: still closes everything, keeps the interrupt
        Thread.currentThread().interrupt();
        try {
            second.close();
        } finally {
            assertThat(Thread.interrupted()).isTrue();
        }
        assertThat(second.health().up()).isFalse();
        second = null;
    }
}
