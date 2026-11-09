/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.sql;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreContext;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** The SQL store against PostgreSQL with the FreeRADIUS table layout (Testcontainers; skipped without Docker). */
class SqlStoreTest {

    private static PostgreSQLContainer postgres;

    @BeforeAll
    static void startPostgres() throws Exception {
        DockerRequirement.check(
                DockerClientFactory.instance().isDockerAvailable(), Boolean.getBoolean("radiusward.require.docker"));
        postgres = new PostgreSQLContainer("postgres:17-alpine");
        postgres.start();
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (true) {
            try (Connection c = connect()) {
                if (c.isValid(5)) {
                    break;
                }
            } catch (SQLException e) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("PostgreSQL not reachable", e);
                }
                Thread.sleep(250);
            }
        }
        try (Connection c = connect();
                Statement st = c.createStatement()) {
            // the FreeRADIUS layout (columns as the radcheck schema names them)
            for (String table : new String[] {"radcheck", "radreply"}) {
                st.execute("CREATE TABLE " + table + " (id serial PRIMARY KEY, username text NOT NULL,"
                        + " attribute text NOT NULL, op varchar(2) NOT NULL DEFAULT '==', value text NOT NULL)");
            }
            for (String table : new String[] {"radgroupcheck", "radgroupreply"}) {
                st.execute("CREATE TABLE " + table + " (id serial PRIMARY KEY, groupname text NOT NULL,"
                        + " attribute text NOT NULL, op varchar(2) NOT NULL DEFAULT '==', value text NOT NULL)");
            }
            st.execute("CREATE TABLE radusergroup (id serial PRIMARY KEY, username text NOT NULL,"
                    + " groupname text NOT NULL, priority integer NOT NULL DEFAULT 1)");
            st.execute("INSERT INTO radcheck (username, attribute, op, value) VALUES"
                    + " ('alice', 'Cleartext-Password', ':=', 'arctangent'),"
                    + " ('alice', 'NAS-IP-Address', '==', '10.0.0.1'),"
                    + " ('bob', 'Crypt-Password', ':=', '$6$salt$x')");
            st.execute("INSERT INTO radreply (username, attribute, op, value) VALUES"
                    + " ('alice', 'Session-Timeout', '=', '3600'), ('alice', 'Reply-Message', '=', 'Hi')");
            st.execute("INSERT INTO radusergroup (username, groupname, priority) VALUES"
                    + " ('alice', 'staff', 1), ('alice', 'guests', 2), ('groupie', 'staff', 1)");
            st.execute("INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES"
                    + " ('staff', 'NAS-Port-Type', '==', 'Ethernet')");
            st.execute("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES"
                    + " ('staff', 'Filter-Id', '=', 'staff'), ('guests', 'Filter-Id', '=', 'guest'),"
                    + " ('guests', 'Session-Timeout', ':=', '600')");
        }
    }

    @AfterAll
    static void stopPostgres() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
    }

    private static IdentityStore store(Map<String, String> extra) {
        Map<String, String> settings = new HashMap<>(Map.of(
                "url", postgres.getJdbcUrl(), "user", postgres.getUsername(), "password", postgres.getPassword()));
        settings.putAll(extra);
        return new SqlStoreProvider().create(new StoreContext("main", settings, 4));
    }

    @Test
    void usersWithCheckReplyAndGroupsInPriorityOrder() throws Exception {
        try (IdentityStore store = store(Map.of())) {
            UserRecord alice = store.lookup("alice").orElseThrow();
            assertThat(alice.check())
                    .containsExactly(
                            new AttributeItem("Cleartext-Password", ":=", "arctangent"),
                            new AttributeItem("NAS-IP-Address", "==", "10.0.0.1"));
            assertThat(alice.reply())
                    .extracting(AttributeItem::attribute)
                    .containsExactly("Session-Timeout", "Reply-Message");
            assertThat(alice.groups()).extracting(UserRecord.Group::name).containsExactly("staff", "guests");
            assertThat(alice.groups().get(0).check())
                    .extracting(AttributeItem::attribute)
                    .containsExactly("NAS-Port-Type");
            assertThat(alice.groups().get(1).check())
                    .as("a group without check items")
                    .isEmpty();
            assertThat(alice.groups().get(1).reply()).hasSize(2);
            assertThat(store.lookup("groupie")).as("known through a group only").isPresent();
            assertThat(store.lookup("nobody")).isEmpty();
            assertThat(store.lookup("alice' OR '1'='1"))
                    .as("parameters, not SQL")
                    .isEmpty();
        }
    }

    @Test
    void concurrentLookupsShareABoundedPool() throws Exception {
        try (IdentityStore store = store(Map.of("pool", "3"))) {
            var lookups = IntStream.range(0, 200)
                    .mapToObj(i -> CompletableFuture.supplyAsync(() -> {
                        try {
                            return store.lookup(i % 2 == 0 ? "alice" : "bob").isPresent();
                        } catch (StoreUnavailableException e) {
                            throw new IllegalStateException(e);
                        }
                    }))
                    .toList();
            assertThat(lookups.stream().map(CompletableFuture::join)).containsOnly(true);
            assertThat(((SqlStore) store).openConnections()).isBetween(1, 3);
        }
    }

    @Test
    void anUnreachableDatabaseIsUnavailableNotUnknown() {
        Map<String, String> settings = Map.of("url", "jdbc:postgresql://127.0.0.1:1/radius", "timeout", "500ms");
        try (IdentityStore store = new SqlStoreProvider().create(new StoreContext("down", settings, 2))) {
            long started = System.nanoTime();
            assertThatThrownBy(() -> store.lookup("alice")).isInstanceOf(StoreUnavailableException.class);
            assertThat(System.nanoTime() - started).as("bounded by the timeout").isLessThan(5_000_000_000L);
        }
    }

    @Test
    void settingsAreValidated() {
        assertThatThrownBy(() -> store(Map.of("schema", "native"))).hasMessageContaining("only radcheck");
        assertThatThrownBy(() -> store(Map.of("table.radcheck", "radcheck; DROP TABLE x")))
                .hasMessageContaining("not a table name");
        assertThatThrownBy(() -> new SqlStoreProvider().create(new StoreContext("x", Map.of(), 2)))
                .hasMessageContaining("auth.store.x.url is required");
        assertThatThrownBy(() -> store(Map.of("timeout", "soon"))).hasMessageContaining("expected a duration");
        assertThat(new SqlStoreProvider().type()).isEqualTo("sql");
    }

    @Test
    void customTableNames() throws Exception {
        try (Connection c = connect();
                Statement st = c.createStatement()) {
            st.execute("CREATE SCHEMA IF NOT EXISTS other");
            st.execute("CREATE TABLE IF NOT EXISTS other.users_check (LIKE radcheck INCLUDING ALL)");
            st.execute("INSERT INTO other.users_check (username, attribute, op, value)"
                    + " VALUES ('dave', 'Cleartext-Password', ':=', 'x')");
        }
        try (IdentityStore store = store(Map.of("table.radcheck", "other.users_check"))) {
            assertThat(store.lookup("dave")).isPresent();
            assertThat(store.lookup("bob")).isEmpty();
        }
    }
}
