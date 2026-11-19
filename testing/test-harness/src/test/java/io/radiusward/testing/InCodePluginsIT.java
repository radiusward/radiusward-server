/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import static org.assertj.core.api.Assertions.assertThat;

import io.qameta.allure.Epic;
import io.qameta.allure.Feature;
import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.CredentialVerifierProvider;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.UserRecord;
import io.radiusward.client.RadiusClient;
import io.radiusward.client.Response;
import io.radiusward.common.config.Config;
import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SinkContext;
import io.radiusward.export.SinkProvider;
import io.radiusward.exporter.ExportConfig;
import io.radiusward.exporter.SinkConfig;
import io.radiusward.server.AuthConfig;
import io.radiusward.server.AuthPlugins;
import io.radiusward.server.RadiusServer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An identity store, a credential verifier and a sink given in code instead of found as plug-ins (ADR 0068, E3): a
 * member exports the committed accounting to the sink, and a RADIUS server answers from the store, the verifier
 * checking the password, as it would with plug-ins of the same types.
 */
@Epic("Plug-ins")
@Feature("Stores, verifiers and sinks given in code")
class InCodePluginsIT {

    @TempDir
    Path dir;

    /** Keeps what it receives in memory; replays from the start after a restart (no stored position). */
    static final class RecordingSink implements AccountingSink {

        final List<ExportEvent> events = new CopyOnWriteArrayList<>();
        volatile String colour;

        @Override
        public void open(SinkContext context) {
            colour = context.settings().get("colour");
        }

        @Override
        public CheckpointStyle checkpointStyle() {
            return CheckpointStyle.IDEMPOTENT_REPLAY;
        }

        @Override
        public long storedPosition() {
            return -1;
        }

        @Override
        public void write(Batch batch) {
            events.addAll(batch.events());
        }

        @Override
        public void close() {}
    }

    /** Knows alice and her VLAN; no password of its own, so the verifier checks it. */
    static final class Directory implements IdentityStore {

        @Override
        public Optional<UserRecord> lookup(String userName) {
            if (!userName.equals("alice")) {
                return Optional.empty();
            }
            return Optional.of(new UserRecord(
                    "alice",
                    List.of(),
                    List.of(new AttributeItem("Reply-Message", "=", "hello from code")),
                    List.of()));
        }

        @Override
        public void close() {}
    }

    @Test
    void aStoreAVerifierAndASinkGivenInCode() throws Exception {
        RecordingSink sink = new RecordingSink();
        SinkConfig recording = new SinkConfig(
                "mine",
                "recording",
                true,
                0,
                Duration.ofHours(1).toMillis(),
                false,
                10,
                20,
                2000,
                Map.of("mode", "sessions+events", "colour", "blue"));
        try (LocalCluster cluster = LocalCluster.builder(dir.resolve("cluster").toFile())
                .members(1)
                .radiusServers(0)
                .export(id -> new ExportConfig(List.of(recording), null, null)
                        .withProviders(SinkProvider.of("recording", () -> sink)))
                .start()) {
            Config settings = Config.of(Map.of(
                    "auth.stores", "directory",
                    "auth.store.directory.type", "in-code",
                    "auth.store.directory.verifier", "passwords",
                    "auth.verifiers", "passwords",
                    "auth.verifier.passwords.type", "in-code-passwords",
                    "auth.plugins.dir", dir.resolve("no-plugins").toString(),
                    "auth.reject.delay", "0s"));
            AuthPlugins plugins = AuthPlugins.stores(IdentityStoreProvider.of("in-code", context -> new Directory()))
                    .withVerifiers(CredentialVerifierProvider.of(
                            "in-code-passwords", context -> new CredentialVerifier() {
                                @Override
                                public Result verifyPassword(String userName, byte[] password) {
                                    return new String(password, StandardCharsets.UTF_8).equals("secret")
                                            ? Result.accepted(null)
                                            : Result.REJECTED;
                                }

                                @Override
                                public void close() {}
                            }));
            AuthConfig auth = new AuthConfig(true, 0, 2, 256, 4096, Duration.ofSeconds(10));
            RadiusServer server = cluster.startServer(
                    1, 0, LocalCluster.registry(), auth, RadiusServer.storeHandler(settings, auth, plugins));
            cluster.awaitLeader();
            cluster.awaitServersConnected();

            try (RadiusClient client = RadiusClient.udp("127.0.0.1", server.authPort(), LocalCluster.SECRET)
                    .timeout(Duration.ofSeconds(2))
                    .retries(2)) {
                Response accept = client.pap("alice", "secret").orElseThrow();
                assertThat(accept.isAccept()).isTrue();
                assertThat(accept.string(18)).contains("hello from code");
                assertThat(client.pap("alice", "wrong").orElseThrow().isReject())
                        .as("the verifier given in code refuses it")
                        .isTrue();
                assertThat(client.pap("bob", "secret").orElseThrow().isReject())
                        .as("unknown to the store")
                        .isTrue();
            }

            try (FakeNas nas = new FakeNas()) {
                nas.ack(server.radiusPort(), AccountingRequest.request(1, 1, "s-in-code", 0));
                nas.ack(server.radiusPort(), AccountingRequest.request(2, 2, "s-in-code", 60));
            }
            LocalCluster.await(
                    Duration.ofSeconds(30), "the sink has the Start and the Stop", () -> sink.events.size() >= 2);
            assertThat(sink.colour).as("the sink's own settings").isEqualTo("blue");
            assertThat(sink.events)
                    .extracting(ExportEvent::acctSessionId, ExportEvent::statusType)
                    .containsExactly(
                            org.assertj.core.groups.Tuple.tuple("s-in-code", 1),
                            org.assertj.core.groups.Tuple.tuple("s-in-code", 2));
        }
    }
}
