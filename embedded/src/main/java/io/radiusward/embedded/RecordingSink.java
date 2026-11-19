/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SinkContext;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * The embedded server's own sink: keeps the committed events for {@link EmbeddedRadiusward#accounting()} and hands
 * them to the {@code onAccounting} listeners. Its position lives in memory, so a paused and resumed member does not
 * deliver an event twice.
 */
final class RecordingSink implements AccountingSink {

    static final String NAME = "embedded";
    static final String TYPE = "embedded-recording";

    private final List<ExportEvent> events = new CopyOnWriteArrayList<>();
    private final List<Consumer<ExportEvent>> listeners = new CopyOnWriteArrayList<>();
    private volatile long position = -1;

    void listen(Consumer<ExportEvent> listener) {
        listeners.add(listener);
    }

    List<ExportEvent> events() {
        return List.copyOf(events);
    }

    int size() {
        return events.size();
    }

    @Override
    public void open(SinkContext context) {}

    @Override
    public CheckpointStyle checkpointStyle() {
        return CheckpointStyle.TRANSACTIONAL;
    }

    @Override
    public long storedPosition() {
        return position;
    }

    @Override
    public void write(Batch batch) {
        if (batch.toPosition() <= position) {
            return;
        }
        for (ExportEvent e : batch.events()) {
            events.add(e);
            listeners.forEach(l -> l.accept(e));
        }
        position = batch.toPosition();
    }

    @Override
    public void close() {}
}
