/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.IntRange;

/**
 * Retransmissions must never change the outcome: a clean stream of events and the same stream with
 * duplicates of already-sent events inserted at random positions end in the same state, digest and
 * applied count.
 */
class DuplicatesPropertyTest {

    record Event(long session, int status, long sessionTime, long octets, int nas) {}

    static List<Event> cleanStream(Random random, int sessions) {
        List<Event> events = new ArrayList<>();
        List<long[]> live = new ArrayList<>(); // session, time
        for (int s = 0; s < sessions; s++) {
            events.add(new Event(s, AccountingStateMachine.STATUS_START, 0, 0, s % 4));
            live.add(new long[] {s, 0});
            while (!live.isEmpty() && random.nextInt(3) == 0) {
                long[] l = live.get(random.nextInt(live.size()));
                l[1] += 60 + random.nextInt(240);
                boolean stop = random.nextInt(4) == 0;
                events.add(new Event(
                        l[0],
                        stop ? AccountingStateMachine.STATUS_STOP : AccountingStateMachine.STATUS_INTERIM,
                        l[1],
                        l[1] * 1000,
                        (int) (l[0] % 4)));
                if (stop) {
                    live.remove(l);
                }
            }
        }
        return events;
    }

    static AccountingStateMachine run(List<Event> events) {
        AccountingStateMachine sm = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(1_000_000));
        long now = 1_000;
        for (Event e : events) {
            now += 10;
            sm.apply(
                    e.session(),
                    e.session() * 7,
                    e.session() * 31 + e.status(),
                    e.sessionTime(),
                    e.nas(),
                    e.status(),
                    AccountingStateMachine.FLAG_SESSION_TIME,
                    e.sessionTime(),
                    0,
                    e.octets(),
                    0,
                    now);
        }
        return sm;
    }

    /** Like {@link #run}, with an Event-Timestamp on every event (session start + session time), as most NAS send. */
    static AccountingStateMachine runWithTimestamps(List<Event> events) {
        AccountingStateMachine sm = new AccountingStateMachine(AccountingStateMachine.Settings.defaults(1_000_000));
        long now = 1_000;
        for (Event e : events) {
            now += 10;
            int outcome = sm.apply(
                    e.session(),
                    e.session() * 7,
                    e.session() * 31 + e.status(),
                    e.sessionTime(),
                    e.nas(),
                    e.status(),
                    AccountingStateMachine.FLAG_SESSION_TIME | AccountingStateMachine.FLAG_EVENT_TIMESTAMP,
                    e.sessionTime(),
                    1_780_000_000L + e.session() + e.sessionTime(),
                    e.octets(),
                    0,
                    now);
            assertThat(Outcomes.acknowledged(outcome)).isTrue();
        }
        return sm;
    }

    @Property(tries = 200)
    void aLateStartNeverChangesTheSessionResult(
            @ForAll @IntRange(min = 1, max = 60) int sessions,
            @ForAll long seed,
            @ForAll @IntRange(max = 30) int delayed) {
        Random random = new Random(seed);
        List<Event> clean = cleanStream(random, sessions);
        List<Event> reordered = new ArrayList<>(clean);
        for (int i = 0; i < delayed; i++) {
            // move a Start behind a later event of its session (its interim or even its stop)
            int from = random.nextInt(reordered.size());
            Event start = reordered.get(from);
            if (start.status() != AccountingStateMachine.STATUS_START) {
                continue;
            }
            int to = from;
            for (int j = from + 1; j < reordered.size(); j++) {
                if (reordered.get(j).session() == start.session() && random.nextBoolean()) {
                    to = j;
                }
            }
            reordered.remove(from);
            reordered.add(to, start);
        }
        AccountingStateMachine a = runWithTimestamps(clean);
        AccountingStateMachine b = runWithTimestamps(reordered);
        assertThat(b.store().size()).isEqualTo(a.store().size());
        assertThat(b.store().activeCount()).isEqualTo(a.store().activeCount());
        for (long session = 0; session < sessions; session++) {
            int sa = a.store().find(session, session * 7);
            int sb = b.store().find(session, session * 7);
            assertThat(b.store().state(sb))
                    .as("state of session %d", session)
                    .isEqualTo(a.store().state(sa));
            assertThat(b.store().sessionTime(sb)).isEqualTo(a.store().sessionTime(sa));
            assertThat(b.store().inputOctets(sb)).isEqualTo(a.store().inputOctets(sa));
        }
    }

    @Property(tries = 300)
    void anyArrivalOrderEndsInTheSameSessions(@ForAll @IntRange(min = 1, max = 40) int sessions, @ForAll long seed) {
        Random random = new Random(seed);
        List<Event> clean = cleanStream(random, sessions);
        List<Event> shuffled = new ArrayList<>(clean);
        // every event of every session in any order: older interims, stops and starts all arrive late
        Collections.shuffle(shuffled, random);
        AccountingStateMachine a = runWithTimestamps(clean); // also asserts every event is acknowledged
        AccountingStateMachine b = runWithTimestamps(shuffled);
        assertThat(b.store().size()).isEqualTo(a.store().size());
        assertThat(b.store().activeCount()).isEqualTo(a.store().activeCount());
        assertThat(b.duplicates()).as("distinct events, nothing is a duplicate").isZero();
        for (long session = 0; session < sessions; session++) {
            int sa = a.store().find(session, session * 7);
            int sb = b.store().find(session, session * 7);
            assertThat(b.store().state(sb))
                    .as("state of session %d", session)
                    .isEqualTo(a.store().state(sa));
            assertThat(b.store().sessionTime(sb)).isEqualTo(a.store().sessionTime(sa));
            assertThat(b.store().inputOctets(sb)).isEqualTo(a.store().inputOctets(sa));
            assertThat(b.store().eventTimestamp(sb)).isEqualTo(a.store().eventTimestamp(sa));
        }
    }

    @Property(tries = 200)
    void duplicatesDoNotChangeTheResult(
            @ForAll @IntRange(min = 1, max = 60) int sessions,
            @ForAll long seed,
            @ForAll @IntRange(max = 200) int dups) {
        Random random = new Random(seed);
        List<Event> clean = cleanStream(random, sessions);
        List<Event> noisy = new ArrayList<>(clean);
        for (int i = 0; i < dups; i++) {
            int at = 1 + random.nextInt(noisy.size());
            Event earlier = noisy.get(random.nextInt(at)); // a duplicate always comes after its original
            noisy.add(at, earlier);
        }
        AccountingStateMachine a = run(clean);
        AccountingStateMachine b = run(noisy);
        assertThat(b.applied()).isEqualTo(a.applied());
        assertThat(b.digest()).isEqualTo(a.digest());
        assertThat(b.store().size()).isEqualTo(a.store().size());
        assertThat(b.store().activeCount()).isEqualTo(a.store().activeCount());
        assertThat(b.duplicates() + b.stale()).isEqualTo((long) dups);
    }
}
