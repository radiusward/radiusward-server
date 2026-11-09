/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.RadiusCode;

/**
 * Decides an Access-Request (Phase 5): authenticates the credentials and authorizes the user. Called on a worker
 * thread — never on the socket thread — so it may wait for an identity store, within its own timeouts; it is shared
 * by all workers and must be thread-safe. Per-request state lives in the {@link AccessContext}.
 */
@FunctionalInterface
public interface AccessHandler {

    int ACCEPT = RadiusCode.ACCESS_ACCEPT;
    int REJECT = RadiusCode.ACCESS_REJECT;
    int CHALLENGE = RadiusCode.ACCESS_CHALLENGE;
    /** No answer: the NAS retransmits or tries another server (e.g. the identity store is unreachable). */
    int DROP = 0;

    /**
     * @return {@link #ACCEPT}, {@link #REJECT}, {@link #CHALLENGE} or {@link #DROP}; reply attributes go to
     *     {@link AccessContext#reply()}
     */
    int handle(AccessContext context);

    /** Adds the handler's own series to {@code /metrics}; none by default. */
    default void writeMetrics(PrometheusWriter w, String gateway) {}
}
