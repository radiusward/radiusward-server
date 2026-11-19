/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.CredentialVerifier;
import io.radiusward.export.AccountingSink;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The settings the builder turns its calls into, without starting anything. */
class BuilderTest {

    private static final Path DIR = Path.of("/tmp/embedded");

    private static final CredentialVerifier VERIFIER = new CredentialVerifier() {
        @Override
        public void close() {}
    };

    @Test
    void defaultsForASmallServerThatForgetsEverything() {
        Map<String, String> v = EmbeddedRadiusward.builder().values(DIR, 23_000);
        assertThat(v)
                .containsEntry("cluster.members", "localhost")
                .containsEntry("cluster.base.port", "23000")
                .containsEntry("archive.file.sync.level", "0")
                .containsEntry("server.listen.host", "127.0.0.1")
                .containsEntry("server.listen.port", "0")
                .containsEntry("server.auth.port", "0")
                .containsEntry("nas.local.address", "127.0.0.1")
                .containsEntry("nas.local.secret", "testing123")
                .containsEntry("auth.stores", "users")
                .containsEntry("export.sinks", "embedded")
                .containsEntry("cluster.data.dir", DIR.resolve("data").toString());
    }

    @Test
    void storesVerifiersSinksAndNasEntriesInTheOrderGiven() {
        Map<String, String> v = EmbeddedRadiusward.builder()
                .user("alice", "a")
                .users(name -> java.util.Optional.empty())
                .users(name -> java.util.Optional.empty())
                .credentialVerifier(VERIFIER)
                .sink(sink())
                .sink("billing", sink())
                .client("office", "10.0.0.0/8", "office-secret")
                .authPort(11812)
                .accountingPort(11813)
                .values(DIR, 23_000);
        assertThat(v)
                .containsEntry("auth.stores", "users, store-1, store-2")
                .containsEntry("auth.store.users.chap", "true")
                .containsEntry("auth.store.store-1.type", "embedded-store-1")
                .containsEntry("auth.store.store-2.verifier", "verifier")
                .containsEntry("auth.verifiers", "verifier")
                .containsEntry("export.sinks", "embedded, sink-1, billing")
                .containsEntry("sink.billing.type", "embedded-billing")
                .containsEntry("nas.office.address", "10.0.0.0/8")
                .containsEntry("server.auth.port", "11812")
                .containsEntry("server.listen.port", "11813")
                .doesNotContainKey("nas.local.address");
        assertThatThrownBy(() -> EmbeddedRadiusward.builder()
                        .credentialVerifier(VERIFIER)
                        .credentialVerifier(VERIFIER))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void settingsComeLastAndReplyItemsAreChecked() {
        assertThat(EmbeddedRadiusward.builder()
                        .setting("auth.reject.delay", "1s")
                        .setting("server.listen.host", "0.0.0.0")
                        .values(DIR, 23_000))
                .containsEntry("auth.reject.delay", "1s")
                .containsEntry("server.listen.host", "0.0.0.0");
        assertThatThrownBy(() -> EmbeddedRadiusward.builder().user("alice", "a", "Class"))
                .as("an item without operator and value")
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theJvmOptionIsThereInTheBuildsTests() {
        EmbeddedRadiusward.checkJvmOption();
    }

    @Test
    void theTemporaryDirectoryIsTheUsersOnly() throws Exception {
        Path dir = EmbeddedRadiusward.temporaryDirectory();
        try {
            if (java.nio.file.FileSystems.getDefault()
                    .supportedFileAttributeViews()
                    .contains("posix")) {
                assertThat(java.nio.file.attribute.PosixFilePermissions.toString(
                                java.nio.file.Files.getPosixFilePermissions(dir)))
                        .isEqualTo("rwx------");
            }
        } finally {
            java.nio.file.Files.delete(dir);
        }
    }

    private static AccountingSink sink() {
        return new AccountingSink() {
            @Override
            public void open(io.radiusward.export.SinkContext context) {}

            @Override
            public CheckpointStyle checkpointStyle() {
                return CheckpointStyle.IDEMPOTENT_REPLAY;
            }

            @Override
            public long storedPosition() {
                return -1;
            }

            @Override
            public void write(io.radiusward.export.Batch batch) {}

            @Override
            public void close() {}
        };
    }
}
