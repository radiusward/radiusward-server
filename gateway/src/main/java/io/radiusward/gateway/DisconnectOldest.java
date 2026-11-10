/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Simultaneous-Use that makes room instead of refusing ({@code coa.simultaneous.use = disconnect-oldest}, ADR 0036):
 * when the cluster denies a place, the user's oldest session (by its first event) gets a Disconnect-Request; once
 * its NAS acknowledged, the place is asked for again until the NAS's Accounting-Stop has freed it, for at most
 * {@code coa.simultaneous.use.wait}. Up to {@link #MAX_DISCONNECTS} sessions, oldest first. Runs on the access worker,
 * which may wait, like for an identity store.
 */
final class DisconnectOldest implements SessionLimits {

    private static final Logger LOG = LogManager.getLogger(DisconnectOldest.class);
    static final int MAX_DISCONNECTS = 3;
    private static final long RETRY_NANOS = 100_000_000L;

    private final SessionLimits limits;
    private final Supplier<CoaService> coa;
    private final Duration wait;

    /** @param coa the gateway's CoA service, available once the gateway runs */
    DisconnectOldest(SessionLimits limits, Supplier<CoaService> coa, Duration wait) {
        this.limits = limits;
        this.coa = coa;
        this.wait = wait;
    }

    @Override
    public long nextSqn(long subscriberKey, long floor) {
        return limits.nextSqn(subscriberKey, floor);
    }

    @Override
    public int reserve(long userKey, long deviceKey, int maxDevices) {
        int result = limits.reserve(userKey, deviceKey, maxDevices);
        CoaService service = coa.get();
        if (result != DENIED || service == null || maxDevices == 0) {
            return result;
        }
        List<ClusterQueries.Session> sessions;
        try {
            sessions = service.queries().userSessions(userKey, CoaService.QUERY_TIMEOUT).stream()
                    .filter(s -> s.identity().length > 0)
                    .sorted(Comparator.comparingInt(ClusterQueries.Session::firstSeen))
                    .toList();
        } catch (TimeoutException e) {
            return UNAVAILABLE; // as when the reservation itself gets no answer
        }
        for (int i = 0; i < sessions.size() && i < MAX_DISCONNECTS; i++) {
            ClusterQueries.Session oldest = sessions.get(i);
            DynamicAuthorization.Result r = service.send(oldest, DynamicAuthorization.DISCONNECT_REQUEST, List.of())
                    .exceptionally(e -> new DynamicAuthorization.Result(DynamicAuthorization.Outcome.UNREACHABLE, 0))
                    .join();
            service.countSimultaneousUse(r.outcome() == DynamicAuthorization.Outcome.ACK);
            if (r.outcome() != DynamicAuthorization.Outcome.ACK) {
                LOG.debug("Simultaneous-Use: disconnecting session {} failed: {}", oldest.attribute(44), r);
                continue;
            }
            long deadline = System.nanoTime() + wait.toNanos();
            while (System.nanoTime() - deadline < 0) {
                result = limits.reserve(userKey, deviceKey, maxDevices);
                if (result != DENIED) {
                    return result;
                }
                LockSupport.parkNanos(RETRY_NANOS); // the NAS's Accounting-Stop has not been applied yet
            }
        }
        return DENIED;
    }
}
