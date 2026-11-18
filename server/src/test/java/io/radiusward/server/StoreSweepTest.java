/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.protocol.MessageHeaderDecoder;
import io.radiusward.protocol.MessageHeaderEncoder;
import io.radiusward.protocol.SessionPageQueryDecoder;
import io.radiusward.protocol.SessionPageReportEncoder;
import io.radiusward.protocol.UserSessionsQueryDecoder;
import io.radiusward.protocol.UserSessionsReportEncoder;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The store sweep (ADR 0036) against a fake cluster that answers its queries: what it does for users the stores accept
 * with other reply items, reject, no longer have or cannot answer for; and its thread — a failing sweep is logged and
 * retried later, stopping ends a sweep or the wait between sweeps.
 */
class StoreSweepTest extends HandlerFixture {

    static final int NAS_ID = 1001; // the entry of HandlerFixture.nas()
    static final CoaConfig.Sweep KEEP = new CoaConfig.Sweep(true, Duration.ofHours(1), 1_000_000, false);
    static final CoaConfig.Sweep DISCONNECT = new CoaConfig.Sweep(true, Duration.ofHours(1), 1_000_000, true);

    private final Cluster cluster = new Cluster();
    private StoreSweep sweep;

    @AfterEach
    void stop() throws Exception {
        if (sweep != null) {
            sweep.stop();
        }
        cluster.close();
    }

    /**
     * Plays the cluster client for a {@link ClusterQueries}: answers page queries from {@link #pages} (by the slot
     * asked for) and user queries with no sessions, recording what was asked.
     */
    static final class Cluster implements AutoCloseable {
        final ClusterQueries queries = new ClusterQueries();
        /** fromSlot → the page answered for it. */
        final Map<Integer, ClusterQueries.Page> pages = new ConcurrentHashMap<>();

        final List<Integer> pagesAsked = new CopyOnWriteArrayList<>();
        final List<Long> usersAsked = new CopyOnWriteArrayList<>();
        private final Thread thread;
        private volatile boolean closed;
        private volatile boolean paused;
        private volatile boolean idle;

        Cluster() {
            thread = new Thread(this::run, "fake-cluster");
            thread.setDaemon(true);
            thread.start();
        }

        private void run() {
            MessageHeaderDecoder header = new MessageHeaderDecoder();
            while (!closed) {
                idle = paused;
                if (paused) {
                    Thread.onSpinWait();
                    continue;
                }
                int read = queries.requests().read((type, buffer, index, length) -> {
                    header.wrap(buffer, index);
                    if (header.templateId() == SessionPageQueryDecoder.TEMPLATE_ID) {
                        SessionPageQueryDecoder q =
                                new SessionPageQueryDecoder().wrapAndApplyHeader(buffer, index, header);
                        pagesAsked.add(q.fromSlot());
                        answerPage(
                                q.correlationId(),
                                pages.getOrDefault(q.fromSlot(), new ClusterQueries.Page(-1, List.of())));
                    } else if (header.templateId() == UserSessionsQueryDecoder.TEMPLATE_ID) {
                        UserSessionsQueryDecoder q =
                                new UserSessionsQueryDecoder().wrapAndApplyHeader(buffer, index, header);
                        usersAsked.add(q.userKey());
                        UnsafeBuffer out = new UnsafeBuffer(new byte[64]);
                        UserSessionsReportEncoder e = new UserSessionsReportEncoder()
                                .wrapAndApplyHeader(out, 0, new MessageHeaderEncoder())
                                .correlationId(q.correlationId());
                        e.sessionsCount(0);
                        queries.deliver(out, 0, MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength());
                    } // anything else: junk that filled the ring
                });
                if (read == 0) {
                    Thread.onSpinWait();
                }
            }
        }

        private void answerPage(long correlationId, ClusterQueries.Page page) {
            UnsafeBuffer out = new UnsafeBuffer(new byte[8192]);
            SessionPageReportEncoder e = new SessionPageReportEncoder()
                    .wrapAndApplyHeader(out, 0, new MessageHeaderEncoder())
                    .correlationId(correlationId)
                    .nextSlot(page.nextSlot());
            SessionPageReportEncoder.SessionsEncoder group =
                    e.sessionsCount(page.sessions().size());
            for (ClusterQueries.Session s : page.sessions()) {
                group.next()
                        .keyHi(s.keyHi())
                        .keyLo(s.keyLo())
                        .nasId(s.nasId())
                        .userKey(s.userKey())
                        .putIdentity(s.identity(), 0, s.identity().length);
            }
            queries.deliver(out, 0, MessageHeaderEncoder.ENCODED_LENGTH + e.encodedLength());
        }

        /** One page with these sessions and no next one. */
        void sessions(ClusterQueries.Session... sessions) {
            pages.put(0, new ClusterQueries.Page(-1, List.of(sessions)));
        }

        /**
         * Stops reading and fills the query ring with junk: every query fails at once with "query ring full" until
         * {@link #resume}.
         */
        void fillRing() {
            paused = true;
            while (!idle) {
                Thread.onSpinWait();
            }
            UnsafeBuffer junk = new UnsafeBuffer(new byte[1024]);
            for (int length : new int[] {1024, 64, 1}) { // to the last aligned record
                while (queries.requests().write(99, junk, 0, length)) {
                    // until full
                }
            }
        }

        /** Reads the ring again: the junk first, then the queries. */
        void resume() {
            paused = false;
        }

        @Override
        public void close() throws InterruptedException {
            closed = true;
            thread.join(2_000);
        }
    }

    /** A session of {@code user} (no User-Name if {@code null}) at the NAS entry {@code nasId}. */
    static ClusterQueries.Session session(int key, int nasId, String user) {
        ByteArrayOutputStream identity = new ByteArrayOutputStream();
        if (user != null) {
            byte[] name = user.getBytes(StandardCharsets.UTF_8);
            identity.write(1);
            identity.write(2 + name.length);
            identity.writeBytes(name);
        }
        byte[] id = ("s-" + key).getBytes(StandardCharsets.UTF_8);
        identity.write(44);
        identity.write(2 + id.length);
        identity.writeBytes(id);
        return new ClusterQueries.Session(0, key, nasId, 0, 0, 0, true, identity.toByteArray());
    }

    static long userKey(String user) {
        byte[] name = user.getBytes(StandardCharsets.UTF_8);
        return UserKeys.user(new UnsafeBuffer(name), 0, name.length);
    }

    private CoaService coa() {
        return new CoaService(
                CoaConfig.DISABLED,
                AuthAgentTest.registry(NasClient.MessageAuthenticatorPolicy.OFF),
                cluster.queries,
                null, // no session is ever found: nothing is sent
                DICTIONARY,
                new RadsecLink(new NasClient[0]),
                Map.of(),
                Map.of(),
                null);
    }

    private StoreSweep sweep(CoaConfig.Sweep config, StoreAccessHandler stores) {
        sweep = new StoreSweep(config, coa(), stores);
        return sweep;
    }

    /** The next sweep, past {@code auth.cache.ttl} so the stores are asked again. */
    private void sweepAgain(StoreSweep s) throws Exception {
        now[0] += 60_000;
        s.sweep();
    }

    private static List<AttributeItem> timeout(int seconds) {
        return List.of(item("Session-Timeout", ":=", Integer.toString(seconds)));
    }

    @Test
    void changedReplyItemsGetACoaAndRejectedUsersADisconnect() throws Exception {
        main.user("alice", List.of(), timeout(3600))
                .user("bob", List.of(), List.of(item("Filter-Id", ":=", "staff")))
                .user("carol", List.of(), List.of());
        cluster.pages.put(
                0,
                new ClusterQueries.Page(
                        7,
                        List.of(
                                session(1, NAS_ID, "alice"),
                                session(2, NAS_ID, null), // no User-Name
                                session(3, 77, "mallory"), // no NAS entry and no NAS address
                                session(4, NAS_ID, "alice")))); // alice's second session: looked up once
        cluster.pages.put(
                7, new ClusterQueries.Page(-1, List.of(session(5, NAS_ID, "bob"), session(6, NAS_ID, "carol"))));
        StoreSweep s = sweep(KEEP, handler());

        sweepAgain(s);
        assertThat(cluster.pagesAsked).as("every page in turn").containsExactly(0, 7);
        assertThat(s.get(StoreSweep.Counter.SWEEPS)).isEqualTo(1);
        assertThat(s.get(StoreSweep.Counter.USERS)).isEqualTo(3);
        assertThat(cluster.usersAsked)
                .as("the first sweep only learns the reply items")
                .isEmpty();

        main.user("alice", List.of(), timeout(600)) // changed
                .user("bob", List.of(), List.of()) // no reply items any more: nothing to send
                .user("carol", List.of(item("Auth-Type", ":=", "Reject")), List.of()); // disabled
        sweepAgain(s);
        assertThat(cluster.usersAsked)
                .as("a CoA for alice, a Disconnect for carol: the sessions of each are asked for")
                .containsExactly(userKey("alice"), userKey("carol"));
        assertThat(s.get(StoreSweep.Counter.CHANGED)).isEqualTo(1);
        assertThat(s.get(StoreSweep.Counter.DISCONNECTED)).isEqualTo(1);
        assertThat(s.get(StoreSweep.Counter.UNAVAILABLE)).isZero();

        sweepAgain(s);
        assertThat(s.get(StoreSweep.Counter.CHANGED))
                .as("the change is sent once")
                .isEqualTo(1);
        assertThat(s.get(StoreSweep.Counter.DISCONNECTED))
                .as("a rejected user is disconnected again while a session stays")
                .isEqualTo(2);
        assertThat(s.get(StoreSweep.Counter.SWEEPS)).isEqualTo(3);
    }

    @Test
    void aStoreOutageChangesNothingAndKeepsWhatWasKnown() throws Exception {
        main.user("alice", List.of(), timeout(3600));
        cluster.sessions(session(1, NAS_ID, "alice"));
        StoreSweep s = sweep(KEEP, handler());
        sweepAgain(s);

        cluster.sessions(session(1, NAS_ID, "alice"), session(2, NAS_ID, "erin")); // erin logs in during the outage
        main.down = true;
        sweepAgain(s);
        assertThat(s.get(StoreSweep.Counter.UNAVAILABLE)).isEqualTo(2);
        assertThat(cluster.usersAsked)
                .as("no store answered: nobody is disconnected")
                .isEmpty();

        main.down = false;
        main.user("alice", List.of(), timeout(600)).user("erin", List.of(), timeout(60));
        sweepAgain(s);
        assertThat(cluster.usersAsked)
                .as("alice's items from before the outage are compared with; erin had none to compare with")
                .containsExactly(userKey("alice"));
        assertThat(s.get(StoreSweep.Counter.CHANGED)).isEqualTo(1);
    }

    @Test
    void aUserNoStoreHasIsKeptAndRemembered() throws Exception {
        main.user("alice", List.of(), timeout(3600));
        cluster.sessions(session(1, NAS_ID, "alice"), session(2, NAS_ID, "eve")); // eve is in no store (EAP-TLS)
        StoreSweep s = sweep(KEEP, handler());
        sweepAgain(s);

        main.users.remove("alice"); // e.g. a store being rewritten
        sweepAgain(s);
        assertThat(cluster.usersAsked).as("coa.sweep.missing = keep").isEmpty();
        assertThat(s.get(StoreSweep.Counter.DISCONNECTED)).isZero();

        main.user("alice", List.of(), timeout(600));
        sweepAgain(s);
        assertThat(cluster.usersAsked)
                .as("alice's items were remembered while she was missing")
                .containsExactly(userKey("alice"));
        assertThat(s.get(StoreSweep.Counter.CHANGED)).isEqualTo(1);
    }

    @Test
    void aUserNoStoreHasIsDisconnectedWhenMissingUsersAre() throws Exception {
        cluster.sessions(session(2, NAS_ID, "eve"));
        StoreSweep s = sweep(DISCONNECT, handler());
        sweepAgain(s);
        assertThat(cluster.usersAsked).containsExactly(userKey("eve"));
        assertThat(s.get(StoreSweep.Counter.DISCONNECTED)).isEqualTo(1);
    }

    /** A store that hands each look-up to {@code hook} first. */
    private StoreAccessHandler handlerWith(java.util.function.Consumer<String> hook) {
        IdentityStore store = new IdentityStore() {
            @Override
            public Optional<UserRecord> lookup(String userName) throws StoreUnavailableException {
                hook.accept(userName);
                return main.lookup(userName);
            }

            @Override
            public void close() {}
        };
        return new StoreAccessHandler(
                new AuthStores(
                        Map.of("main", store),
                        List.of("main"),
                        Map.of(),
                        Map.of(),
                        Duration.ofSeconds(5),
                        1000,
                        12,
                        replyVendors,
                        mschap,
                        verifiers,
                        storeVerifiers,
                        eapConfig),
                DICTIONARY,
                () -> now[0]);
    }

    @Test
    void stoppingDuringASweepSkipsTheRestAndAsksForNoMorePages() throws Exception {
        main.user("alice", List.of(), List.of()).user("bob", List.of(), List.of());
        cluster.pages.put(
                0, new ClusterQueries.Page(5, List.of(session(1, NAS_ID, "alice"), session(2, NAS_ID, "bob"))));
        cluster.pages.put(5, new ClusterQueries.Page(-1, List.of(session(3, NAS_ID, "carol"))));
        List<String> looked = new ArrayList<>();
        sweep = new StoreSweep(KEEP, coa(), handlerWith(user -> {
            looked.add(user);
            sweep.stop(); // never started: only the flag
        }));
        assertThat(sweep.alive()).as("not started").isFalse();
        sweep.sweep();
        assertThat(looked).as("bob is skipped once stopped").containsExactly("alice");
        assertThat(cluster.pagesAsked).as("no next page").containsExactly(0);
    }

    @Test
    void stoppingWhileAUserIsLookedUpEndsTheSweepThread() throws Exception {
        main.user("alice", List.of(), List.of()).user("bob", List.of(), List.of());
        cluster.sessions(session(1, NAS_ID, "alice"), session(2, NAS_ID, "bob"));
        List<String> looked = new CopyOnWriteArrayList<>();
        sweep = new StoreSweep(KEEP, coa(), handlerWith(user -> {
            looked.add(user);
            sweep.stop(); // on the sweep thread: interrupts its pause before the next user
        }));
        sweep.start();
        await(() -> !sweep.alive(), "the sweep thread ends");
        assertThat(looked).containsExactly("alice");
        assertThat(sweep.get(StoreSweep.Counter.SWEEPS))
                .as("the sweep did not finish")
                .isZero();
    }

    @Test
    void aSweepAfterAClusterTimeoutRunsAgainAtTheNextInterval() throws Exception {
        main.user("alice", List.of(), List.of());
        cluster.sessions(session(1, NAS_ID, "alice"));
        cluster.fillRing(); // the cluster client is behind: queries fail at once
        StoreSweep s = sweep(new CoaConfig.Sweep(true, Duration.ofMillis(20), 1_000_000, false), handler());
        s.start();
        Thread.sleep(100);
        assertThat(s.alive()).as("a timeout does not end the thread").isTrue();
        assertThat(s.get(StoreSweep.Counter.SWEEPS)).isZero();
        cluster.resume();
        await(() -> s.get(StoreSweep.Counter.SWEEPS) > 0, "a sweep once the cluster answers");
        assertThat(s.get(StoreSweep.Counter.USERS)).isPositive();
    }

    @Test
    void aStoppedSweepDoesNotRun() {
        StoreSweep s = sweep(KEEP, handler());
        s.stop(); // before start: no thread to interrupt
        s.run();
        assertThat(cluster.pagesAsked).isEmpty();
        assertThat(s.get(StoreSweep.Counter.SWEEPS)).isZero();
    }

    @Test
    void aFailedSweepWaitsForTheNextAndStoppingEndsTheWait() throws Exception {
        // no CoA service: the sweep fails at once and the thread sleeps for the hour to the next one
        StoreSweep sweep = new StoreSweep(new CoaConfig.Sweep(true, Duration.ofHours(1), 20, false), null, null);
        sweep.start();
        Thread.sleep(200);
        assertThat(sweep.alive()).isTrue();
        sweep.stop();
        await(() -> !sweep.alive(), "interrupted in its wait");
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError(what + ": not within 5 s");
            }
            Thread.sleep(10);
        }
    }
}
