/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The {@code Login-Time} check item (ADR 0049), in the format other servers use: comma- or pipe-separated entries,
 * each one or more days followed by an optional {@code HHMM-HHMM} range; without a range the whole day. Days are
 * {@code Mo Tu We Th Fr Sa Su}, {@code Wk} (Monday to Friday), {@code Al} or {@code Any} (every day), and ranges such as
 * {@code Mo-Th}. A range that ends before it starts runs past midnight into the next day. Example:
 * {@code Wk0855-2305,Sa,Su2305-1655}.
 */
final class LoginTime {

    private static final String[] DAYS = {"mo", "tu", "we", "th", "fr", "sa", "su"};
    private static final int WEEK = 7 * 24 * 60;

    /** Allowed intervals as minutes of the week (Monday 00:00 = 0), {@code [start, end)}, end may pass the week. */
    private final List<int[]> intervals;

    private LoginTime(List<int[]> intervals) {
        this.intervals = intervals;
    }

    /** The parsed value, or {@code null} if it is malformed. */
    static LoginTime parse(String text) {
        List<int[]> intervals = new ArrayList<>();
        for (String raw : text.split("[,|]")) {
            String entry = raw.trim().toLowerCase(Locale.ROOT);
            if (entry.isEmpty()) {
                continue;
            }
            boolean[] days = new boolean[7];
            int at = 0;
            boolean any = false;
            while (at < entry.length() && Character.isLetter(entry.charAt(at))) {
                if (entry.startsWith("any", at)) {
                    java.util.Arrays.fill(days, true);
                    at += 3;
                } else if (entry.startsWith("al", at)) {
                    java.util.Arrays.fill(days, true);
                    at += 2;
                } else if (entry.startsWith("wk", at)) {
                    for (int d = 0; d < 5; d++) {
                        days[d] = true;
                    }
                    at += 2;
                } else {
                    int day = day(entry, at);
                    if (day < 0) {
                        return null;
                    }
                    at += 2;
                    int last = day;
                    if (at < entry.length()
                            && entry.charAt(at) == '-'
                            && at + 3 <= entry.length()
                            && Character.isLetter(entry.charAt(at + 1))) {
                        last = day(entry, at + 1);
                        if (last < 0) {
                            return null;
                        }
                        at += 3;
                    }
                    for (int d = day; ; d = (d + 1) % 7) {
                        days[d] = true;
                        if (d == last) {
                            break;
                        }
                    }
                }
                any = true;
            }
            if (!any) {
                return null;
            }
            int from = 0;
            int to = 24 * 60;
            if (at < entry.length()) {
                String range = entry.substring(at);
                if (!range.matches("\\d{4}-\\d{4}")) {
                    return null;
                }
                from = minutes(range.substring(0, 4));
                to = minutes(range.substring(5, 9));
                if (from < 0 || to < 0 || from == to) {
                    return null;
                }
                if (to < from) {
                    to += 24 * 60; // past midnight
                }
            }
            for (int d = 0; d < 7; d++) {
                if (days[d]) {
                    intervals.add(new int[] {d * 24 * 60 + from, d * 24 * 60 + to});
                }
            }
        }
        return intervals.isEmpty() ? null : new LoginTime(List.copyOf(intervals));
    }

    private static int day(String entry, int at) {
        if (at + 2 > entry.length()) {
            return -1;
        }
        String d = entry.substring(at, at + 2);
        for (int i = 0; i < 7; i++) {
            if (DAYS[i].equals(d)) {
                return i;
            }
        }
        return -1;
    }

    private static int minutes(String hhmm) {
        int h = Integer.parseInt(hhmm.substring(0, 2));
        int m = Integer.parseInt(hhmm.substring(2, 4));
        return h > 24 || m > 59 || (h == 24 && m > 0) ? -1 : h * 60 + m;
    }

    /**
     * Seconds left in the window that contains {@code now} (the longest one if several do), or {@code -1} outside
     * every window.
     */
    long secondsLeft(ZonedDateTime now) {
        int minute = (now.getDayOfWeek().getValue() - 1) * 24 * 60 + now.getHour() * 60 + now.getMinute();
        long best = -1;
        for (int[] i : intervals) {
            for (int shift : new int[] {0, WEEK}) { // a window past Sunday midnight holds early Monday too
                int m = minute + shift;
                if (m >= i[0] && m < i[1]) {
                    long left = (long) (i[1] - m) * 60 - now.getSecond();
                    best = Math.max(best, left);
                }
            }
        }
        return best;
    }
}
