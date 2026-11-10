/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.common.config.Config;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Pools on PostgreSQL (ADR 0050): the table filled from the ranges, an address per device that the device gets again,
 * no address of an open exported session, reuse after the lease, an empty pool, concurrent allocations without
 * duplicates. Skipped where Docker is missing, a failure where it is required.
 */
class IpPoolsIT {

    private PostgreSQLContainer postgres;

    @AfterEach
    void stop() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    private Connection connect() throws Exception {
        return DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
    }

    @Test
    void allocateKeepReleaseAndExhaust() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        long deadline = System.nanoTime() + 30_000_000_000L; // the mapped port may lag behind (Colima)
        while (true) {
            try (Connection probe = connect()) {
                if (probe.isValid(5)) {
                    break;
                }
            } catch (java.sql.SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("PostgreSQL not reachable", e);
                }
                Thread.sleep(250);
            }
        }
        try (Connection c = connect();
                Statement s = c.createStatement()) {
            s.execute("CREATE TABLE accounting_session (calling_station_id text, framed_ip inet,"
                    + " stopped_at timestamptz)");
        }
        Map<String, String> values = Map.of(
                "auth.pools", "small, many",
                "auth.pool.small.range", "10.0.0.1-10.0.0.3",
                "auth.pool.small.lease", "2s",
                "auth.pool.many.range", "10.1.0.0/24",
                "auth.pool.sql.url", postgres.getJdbcUrl(),
                "auth.pool.sql.user", postgres.getUsername(),
                "auth.pool.sql.password", postgres.getPassword());
        IpPools pools = IpPools.from(Config.of(values));
        IpPools.from(Config.of(values)); // a second gateway: the rows stay
        IpPools.Pool small = pools.pool("small");

        String a = pools.allocate(small, "alice", "aa-aa");
        String b = pools.allocate(small, "bob", "bb-bb");
        assertThat(a).isNotEqualTo(b).startsWith("10.0.0.");
        assertThat(pools.allocate(small, "alice", "aa-aa"))
                .as("the same device, the same address")
                .isEqualTo(a);
        String c = pools.allocate(small, "carol", "cc-cc");
        assertThat(pools.allocate(small, "dave", "dd-dd")).as("all leased").isNull();

        try (Connection conn = connect();
                Statement s = conn.createStatement()) {
            s.execute("INSERT INTO accounting_session VALUES ('aa-aa', '" + a + "', NULL)");
        }
        Thread.sleep(2500); // the leases ran out
        String d = pools.allocate(small, "dave", "dd-dd");
        assertThat(d).as("not alice's: her session is open").isIn(b, c);
        assertThat(pools.allocate(small, "alice", "aa-aa"))
                .as("alice, from her open session")
                .isEqualTo(a);
        try (Connection conn = connect();
                Statement s = conn.createStatement()) {
            s.execute("UPDATE accounting_session SET stopped_at = now()");
        }

        IpPools.Pool many = pools.pool("many");
        ExecutorService executor = Executors.newFixedThreadPool(8);
        try {
            List<Callable<String>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < 100; i++) {
                String device = "dev-" + i;
                tasks.add(() -> pools.allocate(many, "u", device));
            }
            Set<String> given = new HashSet<>();
            for (Future<String> f : executor.invokeAll(tasks)) {
                assertThat(f.get()).isNotNull();
                given.add(f.get());
            }
            assertThat(given).as("no address twice").hasSize(100);
        } finally {
            executor.shutdown();
        }

        // IPv6 (ADR 0059): delegated prefixes; a prefix stays with its holder while the holder's session is open
        Map<String, String> v6 = new java.util.HashMap<>(values);
        v6.put("auth.pools", "pd");
        v6.put("auth.pool.pd.prefix", "2001:db8:100::/55");
        v6.put("auth.pool.pd.length", "56");
        v6.put("auth.pool.pd.lease", "1s");
        IpPools prefixes = IpPools.from(Config.of(v6));
        IpPools.Pool pd = prefixes.pool("pd");
        String first = prefixes.allocate(pd, "ann", "a6");
        String second = prefixes.allocate(pd, "ben", "b6");
        assertThat(java.util.List.of(first, second))
                .containsExactlyInAnyOrder("2001:db8:100::/56", "2001:db8:100:100::/56");
        assertThat(prefixes.allocate(pd, "cat", "c6")).as("both delegated").isNull();
        try (Connection conn = connect();
                Statement s = conn.createStatement()) {
            s.execute("INSERT INTO accounting_session VALUES ('a6', NULL, NULL)"); // ann's router online
        }
        Thread.sleep(1500);
        assertThat(prefixes.allocate(pd, "cat", "c6"))
                .as("ben's lease ran out, ann is online")
                .isEqualTo(second);
        assertThat(prefixes.allocate(pd, "ann", "a6")).as("ann keeps hers").isEqualTo(first);

        IpPools leaseOnly = new IpPools(Map.of("small", small), IpPools.sql(postgres.getJdbcUrl(), props(), false));
        Thread.sleep(2500);
        assertThat(leaseOnly.allocate(small, "erin", "ee-ee"))
                .as("without accounting_session")
                .isNotNull();
    }

    private java.util.Properties props() {
        java.util.Properties p = new java.util.Properties();
        p.setProperty("user", postgres.getUsername());
        p.setProperty("password", postgres.getPassword());
        return p;
    }
}
