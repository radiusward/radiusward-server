/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.junit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.fail;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.UserRecord;
import io.radiusward.client.AccountingSession;
import io.radiusward.client.RadiusClient;
import io.radiusward.embedded.EmbeddedRadiusward;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.platform.testkit.engine.EngineTestKit;

/**
 * The extension as a developer's tests use it, run through JUnit's test kit: the sample classes below are not run on
 * their own (Surefire and Failsafe skip nested classes).
 */
class RadiuswardExtensionIT {

    /** The servers the sample tests saw, in order. */
    static final List<EmbeddedRadiusward> SEEN = new CopyOnWriteArrayList<>();

    @Radiusward(users = "alice:se:cret", settings = "auth.reject.delay = 0s")
    static class PerClass {

        @Test
        void first(EmbeddedRadiusward radius, RadiusClient nas) {
            SEEN.add(radius);
            assertThat(nas.pap("alice", "se:cret").orElseThrow().isAccept()).isTrue();
        }

        @Test
        void second(EmbeddedRadiusward radius, @Accounting RadiusClient acct) {
            SEEN.add(radius);
            assertThat(acct.send(new AccountingSession("s-1").start())
                            .orElseThrow()
                            .isAcknowledgement())
                    .isTrue();
            assertThat(radius.awaitAccounting(1)).hasSize(1);
        }
    }

    @Radiusward(lifecycle = Radiusward.Lifecycle.PER_TEST)
    static class PerTest {

        @Test
        void first(EmbeddedRadiusward radius) {
            SEEN.add(radius);
            assertThat(radius.accounting()).isEmpty();
        }

        @Test
        void second(EmbeddedRadiusward radius) {
            SEEN.add(radius);
            assertThat(radius.accounting()).as("a fresh server").isEmpty();
        }
    }

    static class InCode {

        @RegisterExtension
        static RadiuswardExtension radius = RadiuswardExtension.configure(b -> b.users(name -> name.equals("carol")
                ? Optional.of(new UserRecord(
                        "carol", List.of(new AttributeItem("Cleartext-Password", ":=", "pw")), List.of(), List.of()))
                : Optional.empty()));

        @Test
        void theDevelopersStore(EmbeddedRadiusward server, RadiusClient nas) {
            SEEN.add(server);
            assertThat(nas.pap("carol", "pw").orElseThrow().isAccept()).isTrue();
        }
    }

    @Radiusward
    static class Failing {

        @Test
        void fails(EmbeddedRadiusward radius) {
            SEEN.add(radius);
            fail("a failing test: the extension must still close the server");
        }
    }

    @Radiusward(users = "no-password")
    static class Misconfigured {

        @Test
        void neverRuns() {
            fail("the malformed annotation must stop the class before any test runs");
        }
    }

    @Test
    void oneServerForAllTestsOfAClassClosedAfterIt() {
        SEEN.clear();
        EngineTestKit.engine("junit-jupiter")
                .selectors(selectClass(PerClass.class))
                .execute()
                .testEvents()
                .assertStatistics(s -> s.started(2).succeeded(2));
        assertThat(SEEN).hasSize(2);
        assertThat(SEEN.get(0)).isSameAs(SEEN.get(1));
        assertThat(SEEN.get(0).member()).as("closed after the class").isNull();
    }

    @Test
    void aFreshServerPerTestWhenAsked() {
        SEEN.clear();
        EngineTestKit.engine("junit-jupiter")
                .selectors(selectClass(PerTest.class))
                .execute()
                .testEvents()
                .assertStatistics(s -> s.started(2).succeeded(2));
        assertThat(SEEN.get(0)).isNotSameAs(SEEN.get(1));
        assertThat(SEEN).allSatisfy(r -> assertThat(r.member()).isNull());
    }

    @Test
    void theDevelopersOwnSetupInCode() {
        SEEN.clear();
        EngineTestKit.engine("junit-jupiter")
                .selectors(selectClass(InCode.class))
                .execute()
                .testEvents()
                .assertStatistics(s -> s.started(1).succeeded(1));
        assertThat(SEEN.getFirst().member()).isNull();
    }

    @Test
    void aFailingTestStillClosesTheServer() {
        SEEN.clear();
        EngineTestKit.engine("junit-jupiter")
                .selectors(selectClass(Failing.class))
                .execute()
                .testEvents()
                .assertStatistics(s -> s.started(1).failed(1));
        assertThat(SEEN.getFirst().member()).as("no member left running").isNull();
    }

    @Test
    void aMistakeInTheAnnotationFailsTheClassWithItsReason() {
        var results = EngineTestKit.engine("junit-jupiter")
                .selectors(selectClass(Misconfigured.class))
                .execute();
        results.testEvents().assertStatistics(s -> s.started(0));
        assertThat(results.containerEvents().failed().stream()
                        .map(e -> e.getPayload(org.junit.platform.engine.TestExecutionResult.class)
                                .flatMap(org.junit.platform.engine.TestExecutionResult::getThrowable)
                                .map(Throwable::getMessage)
                                .orElse("")))
                .anySatisfy(m -> assertThat(m).contains("name:password"));
    }

    @Test
    void classesRunInParallelEachWithItsOwnServer() {
        SEEN.clear();
        EngineTestKit.engine("junit-jupiter")
                .configurationParameter("junit.jupiter.execution.parallel.enabled", "true")
                .configurationParameter("junit.jupiter.execution.parallel.mode.classes.default", "concurrent")
                .selectors(selectClass(PerClass.class), selectClass(InCode.class))
                .execute()
                .testEvents()
                .assertStatistics(s -> s.started(3).succeeded(3));
        assertThat(SEEN).hasSize(3);
        assertThat(SEEN.stream().distinct()).hasSize(2);
    }

    @Test
    void configureNeedsASetup() {
        assertThatThrownBy(() -> RadiuswardExtension.configure(null)).isInstanceOf(NullPointerException.class);
    }
}
