/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.embedded;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.UserRecord;
import io.radiusward.client.AccountingSession;
import io.radiusward.client.RadiusClient;
import io.radiusward.client.Response;
import io.radiusward.client.TerminateCause;
import io.radiusward.export.AccountingSink;
import io.radiusward.export.Batch;
import io.radiusward.export.ExportEvent;
import io.radiusward.export.SinkContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The embedded server as a developer uses it: users, their own store, verifier and sink, accounting, a paused cluster. */
class EmbeddedRadiuswardIT {

    @TempDir
    Path dir;

    @Test
    void usersLogInWithPapChapAndMsChapV2AndGetTheirReplyItems() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .user("alice", "secret", "Class := gold", "Session-Timeout = 3600")
                        .start();
                RadiusClient nas = radius.client()) {
            Response accept = nas.pap("alice", "secret").orElseThrow();
            assertThat(accept.isAccept()).isTrue();
            assertThat(accept.string(25)).contains("gold");
            assertThat(accept.integer(27)).hasValue(3600L);
            assertThat(nas.pap("ALICE", "secret").orElseThrow().isAccept())
                    .as("user names fold case as in the users file")
                    .isTrue();
            assertThat(nas.pap("alice", "wrong").orElseThrow().isReject()).isTrue();
            assertThat(nas.pap("bob", "secret").orElseThrow().isReject()).isTrue();
            assertThat(nas.chap("alice", "secret").orElseThrow().isAccept()).isTrue();
            assertThat(nas.msChapV2("alice", "secret").orElseThrow().isAccept()).isTrue();
        }
    }

    @Test
    void theDevelopersStoreVerifierAndSinkAreUsedAndClosedOnce() {
        AtomicInteger closed = new AtomicInteger();
        IdentityStore store = new IdentityStore() {
            @Override
            public Optional<UserRecord> lookup(String userName) {
                return userName.equals("carol")
                        ? Optional.of(new UserRecord(
                                "carol", List.of(), List.of(new AttributeItem("Class", ":=", "silver")), List.of()))
                        : Optional.empty();
            }

            @Override
            public void close() {
                closed.incrementAndGet();
            }
        };
        CredentialVerifier verifier = new CredentialVerifier() {
            @Override
            public Result verifyPassword(String userName, byte[] password) {
                return new String(password, StandardCharsets.UTF_8).equals("from-ldap")
                        ? Result.accepted(null)
                        : Result.REJECTED;
            }

            @Override
            public void close() {
                closed.incrementAndGet();
            }
        };
        List<ExportEvent> exported = new CopyOnWriteArrayList<>();
        AccountingSink sink = new AccountingSink() {
            @Override
            public void open(SinkContext context) {}

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
                exported.addAll(batch.events());
            }

            @Override
            public void close() {
                closed.incrementAndGet();
            }
        };
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .identityStore(store)
                        .credentialVerifier(verifier)
                        .sink(sink)
                        .setting("sink.sink-1.mode", "sessions+events")
                        .start();
                RadiusClient nas = radius.client();
                RadiusClient acct = radius.accountingClient()) {
            Response accept = nas.pap("carol", "from-ldap").orElseThrow();
            assertThat(accept.isAccept()).isTrue();
            assertThat(accept.string(25)).contains("silver");
            assertThat(nas.pap("carol", "secret").orElseThrow().isReject()).isTrue();
            AccountingSession s = new AccountingSession("s-sink").user("carol");
            assertThat(acct.send(s.start()).orElseThrow().isAcknowledgement()).isTrue();
            EmbeddedRadiusward.await(Duration.ofSeconds(10), "the sink has the Start", () -> !exported.isEmpty());
            assertThat(exported.getFirst().acctSessionId()).isEqualTo("s-sink");
            assertThat(closed).as("still open while running").hasValue(0);
        }
        assertThat(closed).as("store, verifier and sink closed once").hasValue(3);
    }

    @Test
    void accountingIsAcknowledgedAfterTheCommitAndCountedOnce() {
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .client("office", "127.0.0.1", "office-secret")
                        .start();
                RadiusClient acct = radius.accountingClient()) {
            AccountingSession s = new AccountingSession("s-1").user("alice").callingStationId("aa-bb-cc-dd-ee-ff");
            assertThat(acct.send(s.start()).orElseThrow().isAcknowledgement()).isTrue();
            assertThat(radius.session("s-1")).hasValueSatisfying(session -> {
                assertThat(session.active()).isTrue();
                assertThat(session.user()).isEqualTo("alice");
                assertThat(session.nas()).isEqualTo("office");
            });
            assertThat(radius.activeSessions("ALICE"))
                    .extracting(Session.Active::acctSessionId)
                    .containsExactly("s-1");

            var interim = s.interim(Duration.ofMinutes(5), 1_000, 4_000);
            assertThat(acct.send(interim).orElseThrow().isAcknowledgement()).isTrue();
            assertThat(acct.send(interim.delay(3)).orElseThrow().isAcknowledgement())
                    .as("the same interim again, as a NAS resends it")
                    .isTrue();
            assertThat(acct.send(s.stop(Duration.ofMinutes(10), 2_000, 8_000, TerminateCause.USER_REQUEST))
                            .orElseThrow()
                            .isAcknowledgement())
                    .isTrue();

            assertThat(radius.awaitAccounting(3))
                    .extracting(ExportEvent::statusType)
                    .containsExactly(1, 3, 2);
            assertThat(radius.accounting())
                    .as("the resent interim counted once")
                    .hasSize(3);
            assertThat(radius.session("s-1")).hasValueSatisfying(session -> {
                assertThat(session.active()).isFalse();
                assertThat(session.sessionTime()).isEqualTo(Duration.ofMinutes(10));
                assertThat(session.outputOctets()).isEqualTo(8_000);
            });
            assertThat(radius.activeSessions("alice")).isEmpty();
            assertThat(radius.session("never-sent")).isEmpty();
        }
    }

    @Test
    void aPausedClusterLeavesTheNasWithoutAcknowledgementUntilItResumes() {
        List<ExportEvent> heard = new CopyOnWriteArrayList<>();
        try (EmbeddedRadiusward radius =
                        EmbeddedRadiusward.builder().onAccounting(heard::add).start();
                RadiusClient acct = radius.accountingClient()
                        .timeout(Duration.ofMillis(300))
                        .retries(0)) {
            var start = new AccountingSession("s-paused").user("dave").start();
            radius.pauseCluster();
            assertThat(radius.paused()).isTrue();
            assertThat(acct.send(start)).as("no commit, no answer").isEmpty();
            assertThatThrownBy(() -> radius.session("s-paused")).isInstanceOf(IllegalStateException.class);

            radius.resumeCluster();
            RadiusClient patient =
                    radius.accountingClient().timeout(Duration.ofSeconds(2)).retries(3);
            assertThat(patient.send(start).orElseThrow().isAcknowledgement())
                    .as("the NAS resends the same Start after the cluster is back")
                    .isTrue();
            patient.close();
            assertThat(radius.awaitAccounting(1)).as("applied once").hasSize(1);
            EmbeddedRadiusward.await(Duration.ofSeconds(5), "the listener heard it", () -> heard.size() == 1);
            assertThat(radius.session("s-paused"))
                    .hasValueSatisfying(x -> assertThat(x.active()).isTrue());
        }
    }

    @Test
    void severalInParallelEachWithItsOwnPortsAndADirectoryKeptWhenNamed() throws Exception {
        Path kept = dir.resolve("kept");
        try (EmbeddedRadiusward a = EmbeddedRadiusward.builder()
                        .user("alice", "a")
                        .directory(kept)
                        .start();
                EmbeddedRadiusward b =
                        EmbeddedRadiusward.builder().user("alice", "b").start();
                RadiusClient na = a.client();
                RadiusClient nb = b.client()) {
            assertThat(a.authPort()).isNotEqualTo(b.authPort());
            assertThat(na.pap("alice", "a").orElseThrow().isAccept()).isTrue();
            assertThat(nb.pap("alice", "b").orElseThrow().isAccept()).isTrue();
            assertThat(nb.pap("alice", "a").orElseThrow().isReject()).isTrue();
            assertThat(a.directory()).isEqualTo(kept);
            temporary = b.directory();
        }
        assertThat(kept).as("a named directory is kept").isDirectory();
        assertThat(Files.exists(temporary)).as("a temporary one is deleted").isFalse();
    }

    private Path temporary;

    @Test
    void settingsOverrideTheBuilderAndTheJvmOptionIsPresent() {
        EmbeddedRadiusward.checkJvmOption(); // Surefire and Failsafe run with it
        try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                        .user("alice", "secret")
                        .setting("auth.reject.delay", "300ms")
                        .start();
                RadiusClient nas = radius.client()) {
            assertThat(radius.config().duration("auth.reject.delay")).isEqualTo(Duration.ofMillis(300));
            long started = System.nanoTime();
            assertThat(nas.pap("alice", "wrong").orElseThrow().isReject()).isTrue();
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isGreaterThanOrEqualTo(Duration.ofMillis(250));
            assertThat(radius.host()).isEqualTo("127.0.0.1");
            assertThat(radius.member()).isNotNull();
            assertThat(radius.server()).isNotNull();
        }
    }
}
