/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.common.management.PrometheusWriter;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * What the store handler counts: identity store look-ups (by store and result, with their time) and how EAP
 * conversations ended (by method); and, read from the stores when written, EAP TLS reloads and resumptions and the
 * credential verifiers' own counters. Thread-safe: updated by all workers.
 */
final class AuthMetrics {

    static final int SUCCEEDED = 0;
    static final int FAILED = 1;
    static final int TOO_MANY_ROUNDS = 2;
    static final int STORE_UNAVAILABLE = 3;
    private static final List<String> EAP_OUTCOMES =
            List.of("succeeded", "failed", "too_many_rounds", "store_unavailable");

    private final ConcurrentHashMap<String, StoreLookups> lookups = new ConcurrentHashMap<>();
    /** EAP outcomes by method type: {@code type * EAP_OUTCOMES.size() + outcome}. */
    private final AtomicLongArray eapOutcomes = new AtomicLongArray(256 * EAP_OUTCOMES.size());

    /** The look-up counters of {@code store}. */
    StoreLookups lookups(String store) {
        return lookups.computeIfAbsent(store, k -> new StoreLookups());
    }

    /** Counts an EAP conversation of method {@code type} ending in {@code outcome} ({@link #SUCCEEDED} ...). */
    void eapOutcome(int type, int outcome) {
        eapOutcomes.getAndIncrement((type & 0xFF) * EAP_OUTCOMES.size() + outcome);
    }

    long eapOutcome(String method, String outcome) {
        return eapOutcomes.get(EapConfig.type(method) * EAP_OUTCOMES.size() + EAP_OUTCOMES.indexOf(outcome));
    }

    void write(PrometheusWriter w, String gateway, AuthStores stores) {
        StoreLookups.write(w, gateway, new TreeMap<>(lookups));
        if (!stores.eap().methods().isEmpty()) {
            w.counter(
                    "radiusward_gateway_eap_total",
                    "EAP conversations by the outer method and how its method ended (authorization follows a success)");
            for (String method : new TreeSet<>(stores.eap().methods())) {
                for (String outcome : EAP_OUTCOMES) {
                    w.sample(eapOutcome(method, outcome), "gateway", gateway, "method", method, "outcome", outcome);
                }
            }
        }
        EapTlsConfig tls = stores.eap().tls();
        if (tls != null) {
            w.counter(
                    "radiusward_gateway_eap_tls_reloads_total",
                    "Changes of the EAP TLS certificate, key, CA or CRL files: loaded, or failed (previous kept)");
            w.sample(tls.context().reloads(), "gateway", gateway, "result", "loaded");
            w.sample(tls.context().reloadFailures(), "gateway", gateway, "result", "failed");
            w.counter(
                    "radiusward_gateway_eap_tls_resumptions_total",
                    "EAP TLS handshakes that resumed an earlier session (PEAP and TTLS skip their inner method)");
            w.sample(tls.context().resumptions(), "gateway", gateway);
        }
        if (!stores.verifiers().isEmpty()) {
            w.counter(
                    "radiusward_gateway_verifier_events_total",
                    "What credential verifiers did: accepted, rejected, unavailable and their own events");
            new TreeMap<>(stores.verifiers())
                    .forEach((name, verifier) -> new TreeMap<>(verifier.counters())
                            .forEach((event, count) ->
                                    w.sample(count, "gateway", gateway, "verifier", name, "event", event)));
        }
    }
}
