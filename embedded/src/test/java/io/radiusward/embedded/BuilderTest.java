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
    void membersEapSimUsersAndCoa() {
        Map<String, String> v = EmbeddedRadiusward.builder()
                .members(3)
                .radiusServers(2)
                .eap("PEAP", " teap ")
                .simUser("262011000000001", new byte[16], new byte[16])
                .coaPort(13799)
                .values(DIR, 23_000);
        assertThat(v)
                .containsEntry("cluster.members", "localhost, localhost, localhost")
                .containsEntry("auth.eap.methods", "peap, teap")
                .containsEntry("auth.eap.teap.inner", "mschapv2, gtc, basic")
                .containsEntry("nas.local.coa.port", "13799")
                .containsEntry("coa.enabled", "true")
                .containsEntry("auth.stores", "users");
        assertThatThrownBy(() -> EmbeddedRadiusward.builder().simUser("1", new byte[15], new byte[16]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EmbeddedRadiusward.builder().members(4)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> EmbeddedRadiusward.builder().radiusServers(9))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theThrowawayCaSignsTheServerAndClientCertificates(@org.junit.jupiter.api.io.TempDir Path dir)
            throws Exception {
        ThrowawayPki pki = ThrowawayPki.create(dir);
        assertThat(pki.settings()).containsKeys("auth.eap.tls.certificate", "auth.eap.tls.key", "auth.eap.tls.ca");
        String chain = java.nio.file.Files.readString(dir.resolve("server.pem"));
        assertThat(chain.split("-----BEGIN CERTIFICATE-----", -1))
                .as("the chain: the server's certificate, then the CA's")
                .hasSize(3);
        ClientCertificate laptop = pki.client("laptop-1");
        laptop.certificate().verify(pki.ca().getPublicKey());
        pki.ca().verify(pki.ca().getPublicKey());
        assertThat(laptop.certificate().getSubjectX500Principal().getName()).isEqualTo("CN=laptop-1");
        assertThat(laptop.certificate().getExtendedKeyUsage()).containsExactly("1.3.6.1.5.5.7.3.2");
        assertThat(pki.ca().getBasicConstraints()).as("a CA").isGreaterThanOrEqualTo(0);
    }

    @Test
    void theOwnSinkStaysWhenASettingReplacesTheSinkList() {
        assertThat(EmbeddedRadiusward.builder()
                        .setting("export.sinks", "archive")
                        .values(DIR, 23_000))
                .as("a built-in sink from the settings, the embedded one kept first")
                .containsEntry("export.sinks", "embedded, archive");
        assertThat(EmbeddedRadiusward.Builder.withOwnSink("archive, embedded , pg"))
                .isEqualTo("embedded, archive, pg");
        assertThat(EmbeddedRadiusward.Builder.withOwnSink(" ")).isEqualTo("embedded");
        assertThat(EmbeddedRadiusward.Builder.withOwnSink(null)).isEqualTo("embedded");
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
