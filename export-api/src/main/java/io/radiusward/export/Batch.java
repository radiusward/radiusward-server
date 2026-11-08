/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import java.util.List;

/**
 * What a sink writes in one go: the applied events of the log range ({@code fromPosition}, {@code toPosition}]
 * and the latest snapshot of every session that changed in it (at most one per session).
 *
 * @param epoch lease epoch of the exporter; transactional sinks store it with the checkpoint and refuse to
 *     write when a newer epoch has written ({@link FencedException})
 * @param lastEventTime commit time of the entry at {@code toPosition}
 */
public record Batch(
        String sink,
        long epoch,
        long fromPosition,
        long toPosition,
        long lastEventTime,
        List<ExportEvent> events,
        List<SessionSnapshot> sessions) {}
