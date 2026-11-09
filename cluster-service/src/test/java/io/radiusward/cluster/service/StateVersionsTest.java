/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class StateVersionsTest {

    private static final int B = StateVersions.BASELINE;

    @Test
    void theBaselineAppliesUntilSomethingIsActivated() {
        StateVersions v = new StateVersions(B);
        assertThat(v.active()).isEqualTo(B);
        assertThat(v.activeRaw()).isZero();
        assertThat(v.atLeast(B)).isTrue();
        assertThat(v.atLeast(B + 1)).isFalse();
        assertThat(v.lowestSupported()).as("nobody reported").isZero();
    }

    @Test
    void theReportCompletingTheUpgradeActivatesTheNewVersion() {
        StateVersions v = new StateVersions(B + 1);
        // rolling upgrade of a three-member cluster: members 0 and 1 run the new release, 2 still the old one
        assertThat(v.report(0, B + 1, 3, false)).isZero();
        assertThat(v.report(1, B + 1, 3, false)).isZero();
        assertThat(v.report(2, B, 3, false))
                .as("member 2 does not support it yet")
                .isZero();
        assertThat(v.lowestSupported()).isEqualTo(B);
        assertThat(v.active()).isEqualTo(B);
        assertThat(v.report(2, B + 1, 3, false)).as("member 2 upgraded").isEqualTo(B + 1);
        assertThat(v.active()).isEqualTo(B + 1);
        assertThat(v.report(0, B + 1, 3, false)).as("once").isZero();
    }

    @Test
    void aMissingMemberBlocksActivation() {
        StateVersions v = new StateVersions(B + 1);
        assertThat(v.report(0, B + 1, 3, false)).isZero();
        assertThat(v.report(2, B + 1, 3, false)).isZero();
        assertThat(v.lowestSupported()).as("member 1 never reported").isZero();
        assertThat(v.activate(B + 1)).isEqualTo(StateVersions.MEMBERS_NOT_READY);
        assertThat(v.active()).isEqualTo(B);
    }

    @Test
    void holdKeepsAutomaticActivationOffButAllowsItByHand() {
        StateVersions v = new StateVersions(B + 1);
        v.report(0, B + 1, 3, true); // cluster.version.hold on member 0: rollback must stay possible
        v.report(1, B + 1, 3, false);
        assertThat(v.report(2, B + 1, 3, false)).isZero();
        assertThat(v.held()).isTrue();
        assertThat(v.active()).isEqualTo(B);
        assertThat(v.activate(B + 1)).isEqualTo(StateVersions.ACTIVATED);
        assertThat(v.active()).isEqualTo(B + 1);
        assertThat(v.activate(B + 1)).isEqualTo(StateVersions.NOT_NEWER);
        assertThat(v.activate(B)).as("never back").isEqualTo(StateVersions.NOT_NEWER);
    }

    @Test
    void invalidReportsAreIgnored() {
        StateVersions v = new StateVersions(B);
        assertThat(v.report(-1, B + 1, 3, false)).isZero();
        assertThat(v.report(ExportState.MAX_MEMBERS, B + 1, 3, false)).isZero();
        assertThat(v.report(0, B + 1, 0, false)).isZero();
        assertThat(v.clusterSize()).isZero();
    }

    @Test
    void codeOlderThanTheActiveVersionFailsFast() {
        StateVersions v = new StateVersions(B);
        v.restore(B + 1, 3);
        assertThatThrownBy(v::requireSupported)
                .isInstanceOf(StateVersions.UnsupportedStateVersionException.class)
                .hasMessageContaining("applies state version " + (B + 1))
                .hasMessageContaining("supports up to " + B);
    }

    @Test
    void theStateMachineMixesActivationsIntoItsDigestAndFailsOnOlderCode() {
        AccountingStateMachine newer = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(10), B + 1);
        AccountingStateMachine older = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(10), B);
        long before = newer.digest();
        for (int m = 0; m < 2; m++) {
            newer.reportMemberVersion(m, B + 1, 3, false);
            older.reportMemberVersion(m, B + 1, 3, false);
        }
        assertThat(newer.reportMemberVersion(2, B + 1, 3, false)).isEqualTo(B + 1);
        assertThat(newer.atLeast(B + 1)).isTrue();
        assertThat(newer.digest()).isNotEqualTo(before);
        // replaying the same log with code that does not know the version must stop, not apply it wrongly
        assertThatThrownBy(() -> older.reportMemberVersion(2, B + 1, 3, false))
                .isInstanceOf(StateVersions.UnsupportedStateVersionException.class);
    }
}
