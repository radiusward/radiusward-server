/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

/**
 * A destination for exported accounting (ADR 0007, ADR 0018). Implementations are found with
 * {@link java.util.ServiceLoader} through {@link SinkProvider}, on the class path or in {@code plugins/*.jar}.
 *
 * <p>Every sink implements two primitives, whatever the store:
 *
 * <ul>
 *   <li>events: <b>insert if absent</b> by {@code eventId} — writing an event twice changes nothing;
 *   <li>sessions: <b>update only if newer</b> by {@code projectionVersion}.
 * </ul>
 *
 * <p>The exporter calls one sink from one thread. A batch must be durable when {@link #write} returns; until
 * then the exporter keeps it and retries after a failure.
 */
public interface AccountingSink extends AutoCloseable {

    /** How the sink remembers how far it got. */
    enum CheckpointStyle {
        /** the position (with the epoch) is stored in the same transaction as the data: exactly the data written */
        TRANSACTIONAL,
        /** the position is stored after the data; after a crash the last batch is written again (idempotent) */
        IDEMPOTENT_REPLAY
    }

    void open(SinkContext context) throws Exception;

    CheckpointStyle checkpointStyle();

    /** The log position stored by the sink itself, or -1 if it has none; the exporter resumes from it. */
    long storedPosition() throws Exception;

    /**
     * Writes a batch durably.
     *
     * @throws FencedException if an exporter with a newer epoch has already written
     */
    void write(Batch batch) throws Exception;

    @Override
    void close();
}
