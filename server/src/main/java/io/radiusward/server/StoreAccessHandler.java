/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;

import io.radiusward.auth.AttributeItem;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.eap.EapPacket;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.function.LongSupplier;
import org.agrona.collections.Object2LongHashMap;
import org.agrona.collections.Object2ObjectHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Decides PAP and CHAP Access-Requests from the identity stores (Phase 5.3): look the user up (stores in order, a
 * short cache), evaluate check items (password, {@code Auth-Type}, {@code Expiration}, comparisons with the request;
 * groups apply when their own check items match), verify the password, encode the reply items. An unknown user, a
 * failed check or a wrong password is a Reject; a store that cannot answer leaves the request unanswered
 * ({@link #DROP}). Thread-safe: called by all workers.
 */
final class StoreAccessHandler implements AccessHandler, AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(StoreAccessHandler.class);

    private volatile AuthStores stores; // replaced by a reload (ADR 0054)
    private final AuthMetrics metrics = new AuthMetrics();
    private final Dictionary dictionary;
    private final LongSupplier clockMillis;
    private final OnceLogger once = new OnceLogger(LOG);
    private final CheckItems checkItems;
    private final UserDirectory directory;
    private final MsChapAuthenticator msChap;
    private final EapAuthenticator eap;
    private final ReplyEncoder replies;
    private final Admission admission;
    /** Raised by a reload: workers then drop their caches. */
    private volatile int generation;

    /**
     * The caches of one worker, kept in its {@link AccessContext#handlerState()}: only that worker's thread touches
     * them, so they are plain Agrona maps without locks. A user's look-up is cached per worker (at most one look-up
     * per worker and TTL); each map is bounded by {@code auth.cache.max}.
     */
    static final class WorkerCache {
        final Object2ObjectHashMap<String, UserDirectory.Cached> users = new Object2ObjectHashMap<>();
        final Object2LongHashMap<String> verified = new Object2LongHashMap<>(Long.MIN_VALUE);
        final Object2ObjectHashMap<AttributeItem, ReplyEncoder.Encoded> encoded = new Object2ObjectHashMap<>();
        /** The request this worker is deciding, reused for every request. */
        final AuthRequest request = new AuthRequest(this);
        /** The handler's generation the caches belong to (ADR 0054). */
        int generation;
    }

    private static WorkerCache cache(AccessContext context) {
        if (context.handlerState() instanceof WorkerCache cache) {
            return cache;
        }
        WorkerCache cache = new WorkerCache();
        context.handlerState(cache);
        return cache;
    }

    StoreAccessHandler(AuthStores stores, Dictionary dictionary, LongSupplier clockMillis) {
        this.stores = stores;
        this.dictionary = dictionary;
        this.clockMillis = clockMillis;
        this.checkItems = new CheckItems(dictionary, clockMillis, once);
        this.restrictions = new Restrictions(checkItems, clockMillis, once);
        this.totp = new TotpFactor(clockMillis, new java.security.SecureRandom(), once);
        this.msChap = new MsChapAuthenticator(this::stores, once);
        this.passwordChecks = new PasswordChecks(this::stores, msChap, totp, clockMillis, once);
        this.directory = new UserDirectory(
                this::stores, this::policies, dictionary, clockMillis, metrics, checkItems, restrictions, once);
        this.inner = new InnerCredentials(this::stores, this::innerProxy, directory, msChap, passwordChecks, once);
        this.admission = new Admission(dictionary, checkItems, restrictions, once);
        this.replies = new ReplyEncoder(dictionary, once, stores.replyVendors().keySet());
        this.eap = new EapAuthenticator(
                this::stores, this::innerProxy, clockMillis, metrics, directory, inner, msChap, once);
    }

    @Override
    public int handle(AccessContext context) {
        int method = context.credentials().method(context.request());
        WorkerCache cache = cache(context);
        int current = generation;
        if (cache.generation != current) { // the configuration was reloaded
            cache.users.clear();
            cache.verified.clear();
            cache.encoded.clear();
            cache.generation = current;
        }
        AuthRequest auth = cache.request.begin(context, policies); // one set of policies per request
        int result;
        try {
            result = decide(auth, method);
        } finally {
            auth.end();
        }
        if (result == REJECT && MsChapAuthenticator.isMsChap(method)) {
            MsChapAuthenticator.writeError(context, method); // the client shows a proper failure instead of a timeout
        }
        if (result == REJECT && method == AccessRequests.METHOD_EAP && auth.eap.packet != null) {
            EapPacket.failure(auth.eap.packet.identifier()).writeTo(context.reply()); // RFC 3579 §2.6.3
        }
        return result;
    }

    private int decide(AuthRequest auth, int method) {
        AccessContext context = auth.context();
        RadiusPacket request = context.request();
        if (method != AccessRequests.METHOD_PAP
                && method != AccessRequests.METHOD_CHAP
                && !MsChapAuthenticator.isMsChap(method)
                && method != AccessRequests.METHOD_EAP) {
            return REJECT; // none or several methods are never valid
        }
        String userName;
        if (method == AccessRequests.METHOD_EAP) {
            int begun = eap.begin(auth);
            if (begun != ACCEPT) {
                return begun;
            }
            userName = auth.eap.conversation.identity;
        } else {
            userName = request.string(USER_NAME);
        }
        if (userName == null || userName.isEmpty()) {
            return REJECT;
        }
        UserDirectory.Authorization a =
                directory.authorize(auth, userName, method == AccessRequests.METHOD_EAP && eap.outerOptional(auth));
        if (a.code() != ACCEPT) {
            return a.code();
        }
        UserDirectory.Found found = a.found();
        if (method == AccessRequests.METHOD_EAP) {
            a = eap.authenticate(auth, a);
            if (a == EapAuthenticator.ANSWERED) {
                return ACCEPT; // the inner user's home server decided and authorized it (ADR 0044)
            }
            if (a.code() != ACCEPT) {
                return a.code(); // CHALLENGE (another round trip), REJECT or DROP
            }
            found = a.found();
        } else {
            int checked = passwordChecks.check(auth, method, userName, a);
            if (checked != ACCEPT) {
                return checked; // CHALLENGE (TOTP asks for the code), REJECT or DROP
            }
        }
        int admitted = admission.admit(auth, found, a);
        if (admitted != ACCEPT) {
            return admitted;
        }
        String nas = context.nas().name();
        replies.encode(
                auth.caches().encoded,
                a.reply(),
                context.reply(),
                stores.replyVendors().get(nas),
                nas,
                stores.cacheMax());
        msChap.writeSuccess(auth, method); // method attributes: never filtered by vendor
        eap.writeSuccess(auth, method);
        return ACCEPT;
    }

    /** The EAP side (for tests). */
    EapAuthenticator eap() {
        return eap;
    }

    /** EAP conversations in the table (for {@code /state} and tests). */
    int eapConversations() {
        return eap.conversations();
    }

    /** Looks a user with active sessions up again (ADR 0036); see {@link UserDirectory#review}. */
    UserDirectory.Review review(NasClient nas, String userName, byte[] identity) {
        return directory.review(nas, userName, identity);
    }

    // ---- policies (ADR 0049, 0050, 0051, 0053, 0056) ----------------------------------------------------------------

    private volatile AccessPolicies policies = AccessPolicies.NONE;

    /** Takes the settings beyond the stores, at start and on a reload: requests from now on use them. */
    void policies(AccessPolicies policies) {
        this.policies = policies;
    }

    AccessPolicies policies() {
        return policies;
    }

    private final TotpFactor totp;
    private final PasswordChecks passwordChecks;
    private final InnerCredentials inner;
    private final Restrictions restrictions;
    static final String SIMULTANEOUS_USE = "Simultaneous-Use";

    // ---- traces (ADR 0052) ---------------------------------------------------------------------------------------

    static void note(AccessContext context, String step, String detail) {
        Tracer.Trace trace = context.trace();
        if (trace != null) {
            trace.note(step + detail);
        }
    }

    static void because(AccessContext context, String step, String detail) {
        context.reason(step); // a constant: nothing allocated for requests that are not traced
        Tracer.Trace trace = context.trace();
        if (trace != null) {
            trace.because(step + detail);
        }
    }

    /** Inner checks of proxied realms' users go to their home servers when set (ADR 0044). */
    private volatile InnerProxy innerProxy;

    void proxyInner(InnerProxy proxy) {
        this.innerProxy = proxy;
    }

    InnerProxy innerProxy() {
        return innerProxy;
    }

    // ---- credential verifiers (ADR 0025) -------------------------------------------------------

    static String methodName(int method) {
        return switch (method) {
            case AccessRequests.METHOD_PAP -> "PAP";
            case AccessRequests.METHOD_CHAP -> "CHAP";
            case AccessRequests.METHOD_MS_CHAP -> "MS-CHAP";
            case AccessRequests.METHOD_MS_CHAP2 -> "MS-CHAPv2";
            default -> "method " + method;
        };
    }

    /**
     * Takes the stores of a reloaded configuration (ADR 0054): requests from now on use them, workers drop their
     * caches, and the previous stores are closed after {@code grace} (requests still using them finish).
     */
    void reload(AuthStores next, java.time.Duration grace) {
        AuthStores previous = stores;
        replies.reload(next.replyVendors().keySet());
        stores = next;
        generation++;
        directory.reload();
        Thread closer = new Thread(
                () -> {
                    try {
                        Thread.sleep(grace.toMillis());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    previous.close();
                },
                "auth-stores-close");
        closer.setDaemon(true);
        closer.start();
    }

    AuthStores stores() {
        return stores;
    }

    /** The EAP server certificate; {@code null} without EAP-TLS based methods. */
    TlsCredentials eapTls() {
        return stores.eap().tls() == null ? null : stores.eap().tls().context();
    }

    @Override
    public void writeMetrics(PrometheusWriter w, String radiusServer) {
        replies.writeMetrics(w, radiusServer);
        metrics.write(w, radiusServer, stores);
    }

    /** The reply items' encoder and its counters. */
    ReplyEncoder replies() {
        return replies;
    }

    /** Store look-ups and EAP outcomes. */
    AuthMetrics metrics() {
        return metrics;
    }

    private void warnOnce(String key, String message, Object detail) {
        once.warn(key, message, detail);
    }

    private void warnOnce(String key, String message, Object a, Object b) {
        once.warn(key, message, a, b);
    }

    @Override
    public void close() {
        stores.close();
    }
}
