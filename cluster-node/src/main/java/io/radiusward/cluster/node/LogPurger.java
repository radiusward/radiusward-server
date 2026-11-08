/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.node;

import io.aeron.archive.client.AeronArchive;
import io.aeron.cluster.RecordingLog;
import io.radiusward.cluster.service.ServiceStats;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Purges this member's copy of the cluster log (ADR 0014): after a snapshot, everything below
 * {@code min(second-latest snapshot, slowest required sink checkpoint, slowest member)} rounded down to an archive
 * segment boundary, plus snapshot recordings older than the second-latest snapshot. Each member purges only
 * its own archive; the inputs come from the replicated state, so every member computes the same bound.
 */
final class LogPurger {

    private static final Logger LOG = LogManager.getLogger(LogPurger.class);

    /** What one run did; {@code reason} says what bounded it. */
    record Result(long floor, long newStart, long segmentsPurged, int snapshotRecordingsPurged, String reason) {}

    private final File clusterDir;
    private final int memberCount;
    private final boolean dryRun;

    LogPurger(File clusterDir, int memberCount, boolean dryRun) {
        this.clusterDir = clusterDir;
        this.memberCount = memberCount;
        this.dryRun = dryRun;
    }

    Result purge(AeronArchive archive, ServiceStats stats) {
        long logRecording;
        TreeSet<Long> snapshotPositions = new TreeSet<>();
        List<long[]> snapshotRecordings = new ArrayList<>(); // {recordingId, logPosition}
        try (RecordingLog recordingLog = new RecordingLog(clusterDir, false)) {
            logRecording = recordingLog.findLastTermRecordingId();
            for (RecordingLog.Entry e : recordingLog.entries()) {
                if (e.isValid && e.type == RecordingLog.ENTRY_TYPE_SNAPSHOT) {
                    snapshotPositions.add(e.logPosition);
                    snapshotRecordings.add(new long[] {e.recordingId, e.logPosition});
                }
            }
        }
        if (snapshotPositions.size() < 2 || logRecording < 0) {
            return new Result(0, 0, 0, 0, "fewer than two snapshots");
        }
        long secondLatest = snapshotPositions.lower(snapshotPositions.last());
        long exportFloor = stats.exportFloor();
        long memberFloor = stats.memberFloor(memberCount);
        long floor = Math.min(secondLatest, Math.min(exportFloor, memberFloor));
        String reason = floor == secondLatest
                ? "second-latest snapshot"
                : floor == exportFloor ? "slowest required sink" : "slowest member";

        long[] descriptor = new long[3]; // startPosition, segmentFileLength, termBufferLength
        if (archive.listRecording(
                        logRecording,
                        (cs,
                                c,
                                id,
                                st,
                                sp,
                                startPosition,
                                stopPosition,
                                it,
                                segment,
                                term,
                                mtu,
                                session,
                                stream,
                                stripped,
                                original,
                                source) -> {
                            descriptor[0] = startPosition;
                            descriptor[1] = segment;
                            descriptor[2] = term;
                        })
                == 0) {
            return new Result(floor, 0, 0, 0, "log recording " + logRecording + " not found");
        }
        long newStart = floor <= descriptor[0]
                ? descriptor[0]
                : AeronArchive.segmentFileBasePosition(descriptor[0], floor, (int) descriptor[2], (int) descriptor[1]);
        long segments = 0;
        int snapshots = 0;
        if (dryRun) {
            LOG.info("log purge (dry run): would purge the log below {} (floor {}: {})", newStart, floor, reason);
            return new Result(floor, newStart, 0, 0, reason + " (dry run)");
        }
        if (newStart > descriptor[0]) {
            segments = archive.purgeSegments(logRecording, newStart);
        }
        for (long[] snapshot : snapshotRecordings) {
            if (snapshot[1] < secondLatest) {
                try {
                    archive.purgeRecording(snapshot[0]);
                    snapshots++;
                } catch (RuntimeException e) {
                    // already gone (purged by an earlier run); the recording log keeps the stale entry
                }
            }
        }
        if (segments > 0 || snapshots > 0) {
            LOG.info(
                    "log purged below {} ({} segment(s), {} old snapshot recording(s)); bounded by the {}",
                    newStart,
                    segments,
                    snapshots,
                    reason);
        }
        return new Result(floor, newStart, segments, snapshots, reason);
    }
}
