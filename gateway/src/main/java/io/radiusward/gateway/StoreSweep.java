/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.common.management.PrometheusWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLongArray;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Finds users whose store entry changed while they are online (ADR 0036): every {@code coa.sweep.interval}, it pages
 * through the active sessions in the replicated state and looks each user up again, at most {@code coa.sweep.rate}
 * times a second so a directory is not flooded. A user the stores now reject (disabled, {@code Auth-Type := Reject})
 * gets a Disconnect-Request on every session; one whose reply items changed since the previous sweep gets a
 * CoA-Request with the new ones. A user no store has any more is kept unless {@code coa.sweep.missing = disconnect}:
 * EAP-TLS devices with a certificate alone are in no store. Store outages change nothing. Meant for one gateway; a
 * second would only send the same requests again.
 */
final class StoreSweep implements Runnable {

    private static final Logger LOG = LogManager.getLogger(StoreSweep.class);

    enum Counter {
        SWEEPS,
        USERS,
        DISCONNECTED,
        CHANGED,
        UNAVAILABLE
    }

    private final CoaConfig.Sweep config;
    private final CoaService coa;
    private final StoreAccessHandler stores;
    private final AtomicLongArray counts = new AtomicLongArray(Counter.values().length);
    /** Reply items of every user at the previous sweep: a change since is sent as CoA. */
    private Map<String, List<AttributeItem>> previous = new HashMap<>();

    private volatile boolean running = true;
    private Thread thread;

    StoreSweep(CoaConfig.Sweep config, CoaService coa, StoreAccessHandler stores) {
        this.config = config;
        this.coa = coa;
        this.stores = stores;
    }

    void start() {
        thread = new Thread(this, "store-sweep");
        thread.setDaemon(true);
        thread.start();
    }

    void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
        }
    }

    @Override
    public void run() {
        while (running) {
            long started = System.nanoTime();
            try {
                sweep();
            } catch (TimeoutException e) {
                LOG.warn("store sweep: the cluster did not answer, next sweep in {}", config.interval());
            } catch (InterruptedException e) {
                return;
            } catch (RuntimeException e) {
                LOG.warn("store sweep failed", e);
            }
            long rest = config.interval().toNanos() - (System.nanoTime() - started);
            try {
                java.util.concurrent.TimeUnit.NANOSECONDS.sleep(Math.max(rest, 1_000_000L));
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    /** One pass over the active sessions. */
    void sweep() throws TimeoutException, InterruptedException {
        Set<String> seen = new HashSet<>();
        Map<String, List<AttributeItem>> current = new HashMap<>();
        long pause = 1_000_000_000L / config.rate();
        int from = 0;
        do {
            ClusterQueries.Page page = coa.queries().page(from, 64, CoaService.QUERY_TIMEOUT);
            for (ClusterQueries.Session s : page.sessions()) {
                String user = s.attribute(1);
                NasClient nas = coa.nasOf(s);
                if (!running || user == null || nas == null || !seen.add(user)) {
                    continue;
                }
                increment(Counter.USERS);
                StoreAccessHandler.Review review = stores.review(nas, user, s.identity());
                if (review.code() == AccessHandler.DROP) {
                    increment(Counter.UNAVAILABLE);
                    List<AttributeItem> before = previous.get(user);
                    if (before != null) {
                        current.put(user, before); // nothing learnt: compare with what was known next time
                    }
                } else if (review.code() == AccessHandler.REJECT && (review.found() || config.disconnectMissing())) {
                    LOG.info("store sweep: {} is rejected now, disconnecting", user);
                    coa.disconnectUser(user);
                    increment(Counter.DISCONNECTED);
                } else if (review.code() == AccessHandler.REJECT) {
                    List<AttributeItem> before = previous.get(user);
                    if (before != null) {
                        current.put(user, before); // missing but kept (e.g. a store being rewritten): remember
                    }
                } else if (review.code() == AccessHandler.ACCEPT) {
                    current.put(user, review.reply());
                    List<AttributeItem> before = previous.get(user);
                    if (before != null
                            && !before.equals(review.reply())
                            && !review.reply().isEmpty()) {
                        LOG.info("store sweep: reply items of {} changed, sending CoA", user);
                        coa.changeUser(user, review.reply());
                        increment(Counter.CHANGED);
                    }
                }
                Thread.sleep(pause / 1_000_000L, (int) (pause % 1_000_000L));
            }
            from = page.nextSlot();
        } while (from >= 0 && running);
        previous = current;
        increment(Counter.SWEEPS);
    }

    private void increment(Counter c) {
        counts.incrementAndGet(c.ordinal());
    }

    long get(Counter c) {
        return counts.get(c.ordinal());
    }

    void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter(
                "radiusward_gateway_store_sweep_total",
                "Store sweeps, users looked up again and what was done (ADR 0036)");
        for (Counter c : Counter.values()) {
            w.sample(get(c), "gateway", gateway, "result", c.name().toLowerCase(java.util.Locale.ROOT));
        }
    }
}
