/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.units;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;

class UnitsTest {

    @Test
    void durationsWithEveryUnit() {
        assertThat(Units.duration("250ms", null)).isEqualTo(Duration.ofMillis(250));
        assertThat(Units.duration("10s", null)).isEqualTo(Duration.ofSeconds(10));
        assertThat(Units.duration("5m", null)).isEqualTo(Duration.ofMinutes(5));
        assertThat(Units.duration("2h", null)).isEqualTo(Duration.ofHours(2));
        assertThat(Units.duration("90d", null)).isEqualTo(Duration.ofDays(90));
        assertThat(Units.duration(" 3 S ", null)).as("case and spaces").isEqualTo(Duration.ofSeconds(3));
    }

    @Test
    void aBareNumberTakesTheGivenUnitOrNeedsOne() {
        assertThat(Units.duration("1500", ChronoUnit.MILLIS)).isEqualTo(Duration.ofMillis(1500));
        assertThat(Units.duration("3", ChronoUnit.SECONDS)).isEqualTo(Duration.ofSeconds(3));
        assertThat(Units.duration("0", null)).isEqualTo(Duration.ZERO);
        assertThatThrownBy(() -> Units.duration("30", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("with a unit");
    }

    @Test
    void notADuration() {
        for (String bad : new String[] {"", "s", "1.5s", "-1s", "10x", "1 week"}) {
            assertThatThrownBy(() -> Units.duration(bad, ChronoUnit.SECONDS))
                    .as(bad)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("expected a duration");
        }
    }

    @Test
    void sizes() {
        assertThat(Units.bytes("512")).isEqualTo(512);
        assertThat(Units.bytes("64k")).isEqualTo(64 << 10);
        assertThat(Units.bytes("256M")).isEqualTo(256L << 20);
        assertThat(Units.bytes("1gb")).isEqualTo(1L << 30);
        assertThat(Units.bytes("4 mb")).isEqualTo(4L << 20);
        for (String bad : new String[] {"", "k", "1.5m", "-1", "1t"}) {
            assertThatThrownBy(() -> Units.bytes(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void listsAreTrimmedAndLeaveOutEmptyItems() {
        assertThat(Units.list(" a, b ,,c ,")).containsExactly("a", "b", "c");
        assertThat(Units.list("group with spaces, other")).containsExactly("group with spaces", "other");
        assertThat(Units.list("")).isEmpty();
        assertThat(Units.list(" , ")).isEmpty();
    }

    @Test
    void wordsAreSeparatedByCommasOrSpaces() {
        assertThat(Units.words("ldap://a  ldap://b,ldap://c ,\tldap://d"))
                .containsExactly("ldap://a", "ldap://b", "ldap://c", "ldap://d");
        assertThat(Units.words(" ")).isEmpty();
    }

    @Test
    void hexWithOrWithoutPrefixInEitherCase() {
        assertThat(Units.hex("0x00ff", 2)).containsExactly(0, 0xff);
        assertThat(Units.hex(" 0XAbCd ", -1)).containsExactly(0xab, 0xcd);
        assertThat(Units.hex("", -1)).isEmpty();
        assertThatThrownBy(() -> Units.hex("0x00ff", 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("3 bytes");
        for (String bad : new String[] {"0x0", "xyz", "0x 00"}) {
            assertThatThrownBy(() -> Units.hex(bad, -1)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
