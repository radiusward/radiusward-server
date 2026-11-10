/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;

class LoginTimeTest {

    /** 2027-01-11 is a Monday. */
    static ZonedDateTime at(int dayOfJanuary, int hour, int minute) {
        return ZonedDateTime.of(2027, 1, dayOfJanuary, hour, minute, 0, 0, ZoneOffset.UTC);
    }

    @Test
    void daysRangesAndWindows() {
        LoginTime t = LoginTime.parse("Wk0855-2305,Sa");
        assertThat(t.secondsLeft(at(11, 9, 0))).isEqualTo((23 * 60 + 5 - 9 * 60) * 60L);
        assertThat(t.secondsLeft(at(11, 8, 0))).isEqualTo(-1);
        assertThat(t.secondsLeft(at(16, 23, 59))).as("Saturday, whole day").isEqualTo(60);
        assertThat(t.secondsLeft(at(17, 12, 0))).as("Sunday").isEqualTo(-1);

        LoginTime days = LoginTime.parse("Mo-We|Any0000-0100");
        assertThat(days.secondsLeft(at(13, 12, 0))).as("Wednesday").isEqualTo(12 * 3600L);
        assertThat(days.secondsLeft(at(14, 0, 30))).as("Thursday 00:30").isEqualTo(30 * 60L);
        assertThat(days.secondsLeft(at(14, 2, 0))).isEqualTo(-1);
        assertThat(LoginTime.parse("Fr-Mo").secondsLeft(at(17, 12, 0)))
                .as("wraps the week")
                .isPositive();
        assertThat(LoginTime.parse("al").secondsLeft(at(12, 0, 0))).isEqualTo(24 * 3600L);
    }

    @Test
    void windowsPastMidnightAndPastSunday() {
        LoginTime night = LoginTime.parse("Su2200-0600");
        assertThat(night.secondsLeft(at(17, 23, 0))).isEqualTo(7 * 3600L);
        assertThat(night.secondsLeft(at(18, 5, 0)))
                .as("Monday early, from Sunday's window")
                .isEqualTo(3600);
        assertThat(night.secondsLeft(at(18, 7, 0))).isEqualTo(-1);
        ZonedDateTime withSeconds = Instant.parse("2027-01-17T23:00:30Z").atZone(ZoneOffset.UTC);
        assertThat(night.secondsLeft(withSeconds)).isEqualTo(7 * 3600L - 30);
    }

    @Test
    void malformedValues() {
        for (String bad :
                new String[] {"", "Xy", "Mo25", "Mo0900", "Mo0900-0900", "Mo2500-0100", "0900-1000", "Mo-Xx"}) {
            assertThat(LoginTime.parse(bad)).as(bad).isNull();
        }
    }
}
