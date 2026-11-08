/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.linux;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Catch-up rate of the PostgreSQL sink per storage variant (the P3.4 benchmark matrix, part that changes the
 * write path): a backlog of ~60k events is built with PostgreSQL down, then drained; it must drain faster than
 * the intake (3k events/s here). Prints rows/s, bytes per row and table sizes.
 */
class ExportThroughputIT {

    private record Variant(String name, String mode, String attributes) {}

    @Test
    void backlogDrainsFasterThanIntake() {
        List<Variant> variants = List.of(
                new Variant("sessions", "sessions", "json"),
                new Variant("events, residual json", "sessions+events", "json"),
                new Variant("events, raw bytes", "sessions+events", "raw"),
                new Variant("events, typed columns only", "sessions+events", "none"));
        List<String> table = new ArrayList<>();
        for (Variant v : variants) {
            try (ContainerCluster cluster = new ContainerCluster(
                    "export-throughput-" + v.mode().replace('+', '-') + "-" + v.attributes(),
                    ContainerCluster.Options.defaults()
                            .postgres(true)
                            .env("RADIUSWARD_SINK_PG_MODE", v.mode())
                            .env("RADIUSWARD_SINK_PG_ATTRIBUTES", v.attributes()))) {
                cluster.start();
                cluster.stopPostgres();
                LoadResult load = cluster.load(10, 15_000, 3000, Duration.ofSeconds(20), "/tmp/acks.csv");
                assertThat(load.failed()).isZero();
                long backlog = cluster.sinks().get("pg").lagBytes();
                cluster.startPostgres();
                long started = System.nanoTime();
                cluster.awaitExportCaughtUp("pg", Duration.ofMinutes(5));
                double seconds = (System.nanoTime() - started) / 1e9;
                long sessions = Long.parseLong(cluster.psql("SELECT count(*) FROM accounting_session"));
                long events = Long.parseLong(cluster.psql("SELECT count(*) FROM accounting_event"));
                long rows = sessions + events;
                long eventBytes = Long.parseLong(cluster.psql("SELECT pg_total_relation_size('accounting_event')"
                        + " + coalesce((SELECT sum(pg_total_relation_size(inhrelid)) FROM pg_inherits"
                        + " WHERE inhparent = 'accounting_event'::regclass), 0)"));
                long sessionBytes = Long.parseLong(cluster.psql("SELECT pg_total_relation_size('accounting_session')"));
                double events_s = load.acked() / seconds;
                table.add(String.format(
                        "| %s | %d | %.0f s | %.0f events/s | %d / %d | %s | %s |",
                        v.name(),
                        backlog,
                        seconds,
                        events_s,
                        sessions,
                        events,
                        events == 0 ? "-" : (eventBytes / events) + " B",
                        (sessionBytes / Math.max(1, sessions)) + " B"));
                assertThat(events_s)
                        .as(v.name() + ": drains faster than the 3k/s intake")
                        .isGreaterThan(3000);
                assertThat(cluster.verifyExport("/tmp/acks.csv").getStdout()).contains("lost=0");
                assertThat(rows).isPositive();
            }
        }
        System.out.println(
                "| variant | backlog bytes | drain time | drain rate | sessions / events | bytes per event row | bytes per session row |");
        System.out.println("|---|---|---|---|---|---|---|");
        table.forEach(System.out::println);
    }
}
