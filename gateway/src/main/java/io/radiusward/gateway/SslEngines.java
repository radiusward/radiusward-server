/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;

/** What every {@link SSLEngine} driver in the gateway does the same way: TLS and DTLS, server and client. */
final class SslEngines {

    private SslEngines() {}

    /**
     * Runs the engine's delegated tasks on this thread (handshake status {@code NEED_TASK}): certificate checks, and
     * OCSP, which may wait for its timeout (ADR 0033).
     */
    static void runTasks(SSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    /** {@code buffer}'s contents (flipped for reading) in a buffer {@code more} bytes larger, left for writing. */
    static ByteBuffer grow(ByteBuffer buffer, int more) {
        ByteBuffer larger = ByteBuffer.allocate(buffer.capacity() + more);
        buffer.flip();
        larger.put(buffer);
        return larger;
    }
}
