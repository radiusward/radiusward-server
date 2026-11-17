/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.LongSupplier;
import org.agrona.collections.Object2LongHashMap;
import org.agrona.collections.Object2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;
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
    private static final int USER_NAME = 1;
    private static final int CALLING_STATION_ID = 31;

    private volatile AuthStores stores; // replaced by a reload (ADR 0054)
    private final AuthMetrics metrics = new AuthMetrics();
    private final Dictionary dictionary;
    private final LongSupplier clockMillis;
    private final OnceLogger once = new OnceLogger(LOG);
    private final CheckItems checkItems;
    private final UserDirectory directory;
    private final MsChapAuthenticator msChap;
    private final ReplyEncoder replies;
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
        this.checkItems = new CheckItems(dictionary, clockMillis, this::zone, once);
        this.restrictions = new Restrictions(checkItems, clockMillis, once);
        this.totp = new TotpFactor(clockMillis, new java.security.SecureRandom(), once);
        this.msChap = new MsChapAuthenticator(this::stores, once);
        this.passwordChecks = new PasswordChecks(this, msChap, clockMillis, once);
        this.directory =
                new UserDirectory(this::stores, dictionary, clockMillis, metrics, checkItems, restrictions, once);
        this.inner = new InnerCredentials(this, directory, msChap, passwordChecks, once);
        this.replies = new ReplyEncoder(dictionary, once, stores.replyVendors().keySet());
        this.conversations = new EapConversations(stores.eap().conversations());
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
        AuthRequest auth = cache.request.begin(context);
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
            int begun = eapBegin(auth);
            if (begun != ACCEPT) {
                return begun;
            }
            userName = auth.eap.conversation.identity;
        } else {
            userName = string(request, USER_NAME);
        }
        if (userName == null || userName.isEmpty()) {
            return REJECT;
        }
        UserDirectory.Authorization a =
                directory.authorize(auth, userName, method == AccessRequests.METHOD_EAP && outerOptional(auth));
        if (a.code() != ACCEPT) {
            return a.code();
        }
        UserDirectory.Found found = a.found();
        String authType = a.authType();
        List<AttributeItem> passwords = a.passwords();
        if (method == AccessRequests.METHOD_EAP) {
            int round = eapRound(auth, found, authType, passwords);
            if (round != ACCEPT) {
                return round; // CHALLENGE (another round trip), REJECT or DROP
            }
            EapConversations.Conversation c = auth.eap.conversation;
            String inner = c.method == null ? null : c.method.innerIdentity();
            InnerProxy p = innerProxy;
            if (inner != null && p != null && p.realm(inner) != null) {
                // the inner user's home server decided and authorized it (ADR 0044); its reply is ours
                if (c.proxiedReply == null) {
                    return REJECT; // no verdict from it in this conversation
                }
                writeEapSuccess(auth, method);
                context.reply().rawAttributes(new UnsafeBuffer(c.proxiedReply), 0, c.proxiedReply.length);
                return ACCEPT;
            }
            if (inner != null) { // a tunnel: the inner user is the one authorized (ADR 0029)
                a = directory.authorize(auth, inner, c.method.innerOptional());
                if (a.code() != ACCEPT) {
                    return a.code();
                }
                found = a.found();
            }
        } else {
            boolean firstFactor = !authType.equalsIgnoreCase("Accept");
            boolean challenge = false;
            String secret = TotpFactor.secretOf(a.restrictions());
            if (secret != null) {
                int second = totp.check(
                        context, method, userName, secret, () -> papPassword(auth), rest -> auth.papPassword = rest);
                if (second == TotpFactor.CODE_OK) {
                    firstFactor = false; // the password was checked in the round that asked for the code
                } else if (second == TotpFactor.ASK) {
                    challenge = true;
                } else if (second != ACCEPT) {
                    return second;
                }
            }
            if (firstFactor) {
                String verifier = passwordChecks.verifierFor(authType, found.store(), passwords);
                int checked = verifier != null
                        ? passwordChecks.verify(auth, method, verifier, userName)
                        : passwordChecks.authenticate(auth, method, found, userName, passwords) ? ACCEPT : REJECT;
                if (checked != ACCEPT) {
                    return checked;
                }
            }
            if (challenge) {
                return totp.challenge(context, userName);
            }
        }
        if (a.limit() != null) {
            int decision = restrictions.limit(context, request, found.store(), a.limit());
            if (decision != ACCEPT) {
                because(context, "Simultaneous-Use not granted: ", a.limit());
                return decision;
            }
        }
        int restricted = restrictions.restrict(context, found.user().userName(), a);
        if (restricted != ACCEPT) {
            return restricted;
        }
        int pooled = addresses.assign(context, request, found.user().userName(), a);
        if (pooled != ACCEPT) {
            return pooled;
        }
        RulesFile r = rules;
        if (r != null && !r.current().apply(ruleRequest(request, found.user()), a.reply())) {
            because(context, "rejected by a rule of ", "auth.rules");
            return REJECT;
        }
        Cui c = cui;
        if (c != null) {
            c.apply(request, found.user().userName(), a.reply()); // ADR 0056
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
        writeEapSuccess(auth, method);
        return ACCEPT;
    }

    /** Looks a user with active sessions up again (ADR 0036); see {@link UserDirectory#review}. */
    UserDirectory.Review review(NasClient nas, String userName, byte[] identity) {
        return directory.review(nas, userName, identity);
    }

    // ---- EAP (RFC 3748, RFC 3579; ADR 0026) -----------------------------------------------------

    private static final int STATE = 24;

    /**
     * Reads the EAP response and finds its conversation: a new one for an Identity response without State, the one
     * the State names otherwise. {@link #ACCEPT} to go on; a malformed packet is discarded ({@link #DROP}), an
     * unknown or used State is rejected.
     */
    private int eapBegin(AuthRequest auth) {
        AccessContext context = auth.context();
        RadiusPacket request = context.request();
        EapPacket eap = EapPacket.from(request);
        if (eap == null || eap.code() != EapPacket.CODE_RESPONSE) {
            return DROP; // RFC 3579 §2.6.2: silently discard
        }
        AuthRequest.EapRound round = auth.eap;
        round.packet = eap;
        int at = request.findAttribute(STATE);
        if (at < 0) {
            if (eap.type() != EapPacket.TYPE_IDENTITY) {
                return REJECT;
            }
            String identity = new String(eap.data(), StandardCharsets.UTF_8)
                    .replace("\0", "")
                    .trim();
            if (identity.isEmpty()) {
                return REJECT;
            }
            round.conversation = new EapConversations.Conversation(context.nas().name(), identity);
            return ACCEPT;
        }
        byte[] state = new byte[(request.buffer().getByte(at + 1) & 0xFF) - 2];
        request.buffer().getBytes(at + 2, state);
        round.state = state;
        round.conversation = conversations.take(state, context.nas().name(), clockMillis.getAsLong());
        return round.conversation == null ? REJECT : ACCEPT;
    }

    /**
     * One round of the conversation's method: starts it after the Identity response, follows a Nak, or gives the
     * method the peer's response. Returns {@link #CHALLENGE} with the next request and a new State, {@link #ACCEPT}
     * when the method succeeded, {@link #REJECT} when it failed, {@link #DROP} when the table is full or the response
     * answers another request.
     */
    private int eapRound(AuthRequest auth, UserDirectory.Found found, String authType, List<AttributeItem> passwords) {
        AccessContext context = auth.context();
        AuthRequest.EapRound round = auth.eap;
        EapPacket eap = round.packet;
        EapConversations.Conversation c = round.conversation;
        if (authType.equalsIgnoreCase("Accept")) {
            return ACCEPT; // no credential to check: EAP-Success right away
        }
        EapMethod.Credentials credentials = new EapMethod.Credentials(
                passwords, stores.chap().getOrDefault(found.store(), false), new EapMethod.InnerAuth() {
                    @Override
                    public EapMethod.Inner msChapV2(String user, EapMethod.MsChapV2 exchange) {
                        return inner.msChapV2(auth, user, exchange);
                    }

                    @Override
                    public EapMethod.Inner password(String user, byte[] password) {
                        return inner.password(auth, user, password);
                    }

                    @Override
                    public EapMethod.Inner chap(String user, int identifier, byte[] challenge, byte[] response) {
                        return inner.chap(auth, user, identifier, challenge, response);
                    }

                    @Override
                    public EapMethod.Inner msChapV1(String user, byte[] challenge, byte[] ntResponse) {
                        return inner.msChap(auth, user, challenge, ntResponse, false);
                    }

                    @Override
                    public EapMethod.Subscriber subscriber(String imsi) {
                        return simSubscriber(auth, imsi);
                    }

                    @Override
                    public long nextSqn(String imsi, long floor) {
                        byte[] name = imsi.getBytes(StandardCharsets.US_ASCII);
                        return context.sessionLimits()
                                .nextSqn(UserKeys.user(new UnsafeBuffer(name), 0, name.length), floor);
                    }
                });
        EapMethod.Step step;
        if (c.method == null) {
            c.method = stores.eap().create(EapConfig.type(stores.eap().methods().get(0)), c.identity);
            if (c.method == null) {
                return REJECT; // not reached: configuration refuses TLS methods without a certificate
            }
            step = c.method.start(eap.identifier() + 1, credentials);
        } else if (eap.identifier() != c.identifier) {
            return DROP; // a response to an earlier request
        } else if (eap.type() == EapPacket.TYPE_NAK) {
            EapMethod offered = null;
            for (byte t : eap.data()) {
                int type = t & 0xFF;
                if (type != c.method.type()
                        && stores.eap().methods().stream().anyMatch(m -> EapConfig.type(m) == type)) {
                    offered = stores.eap().create(type, c.identity);
                    break;
                }
            }
            if (offered == null || c.rounds > 1) {
                return REJECT; // nothing both sides support, or a Nak after the method began
            }
            c.method = offered;
            step = c.method.start(eap.identifier() + 1, credentials);
        } else if (eap.type() != c.method.type()) {
            return REJECT;
        } else {
            step = c.method.process(eap.identifier(), eap.data(), credentials);
        }
        if (step.unavailable()) {
            metrics.eapOutcome(c.method.type(), AuthMetrics.STORE_UNAVAILABLE);
            // the inner credential cannot be checked now: keep the conversation for the peer's retransmission
            if (round.state != null) {
                conversations.putBack(round.state, c, clockMillis.getAsLong());
            }
            return DROP;
        }
        if (++c.rounds > stores.eap().maxRounds()) {
            metrics.eapOutcome(c.method.type(), AuthMetrics.TOO_MANY_ROUNDS);
            return REJECT;
        }
        if (step.done()) {
            round.msk = step.msk();
            metrics.eapOutcome(c.method.type(), step.success() ? AuthMetrics.SUCCEEDED : AuthMetrics.FAILED);
            return step.success() ? ACCEPT : REJECT;
        }
        long now = clockMillis.getAsLong();
        c.identifier = (eap.identifier() + 1) & 0xFF;
        c.expires = now + stores.eap().timeout().toMillis();
        byte[] state = conversations.put(c, now);
        if (state == null) {
            warnOnce("eap-full", "EAP conversations full (auth.eap.conversations): new rounds are not answered", null);
            return DROP;
        }
        EapPacket.request(c.identifier, c.method.type(), step.request()).writeTo(context.reply());
        context.reply().attribute(STATE, state);
        return CHALLENGE;
    }

    /** Whether this conversation's method (or the one it will start, or a Nak asks for) needs no store entry. */
    private boolean outerOptional(AuthRequest auth) {
        AccessContext context = auth.context();
        AuthRequest.EapRound round = auth.eap;
        EapConversations.Conversation c = round.conversation;
        if (c.method != null) {
            if (round.packet.type() == EapPacket.TYPE_NAK) {
                for (byte t : round.packet.data()) {
                    if (stores.eap().outerOptional(t & 0xFF)) {
                        return true;
                    }
                }
            }
            return stores.eap().outerOptional(c.method.type());
        }
        return stores.eap().outerOptional(EapConfig.type(stores.eap().methods().get(0)));
    }

    /** EAP-Success and, for methods that derive one, the MSK as MS-MPPE keys (RFC 3748 §7.10, RFC 2548). */
    private void writeEapSuccess(AuthRequest auth, int method) {
        AccessContext context = auth.context();
        AuthRequest.EapRound round = auth.eap;
        if (method != AccessRequests.METHOD_EAP || round.packet == null) {
            return;
        }
        EapPacket.success(round.packet.identifier()).writeTo(context.reply());
        if (round.msk != null && round.msk.length >= 64) {
            msChap.writeMppeKeys(context, Arrays.copyOfRange(round.msk, 32, 64), Arrays.copyOfRange(round.msk, 0, 32));
        }
    }

    /** Conversations in the table (for {@code /state} and tests). */
    int eapConversations() {
        return conversations.size();
    }

    private final EapConversations conversations;

    // ---- restrictions and IP pools (ADR 0049, ADR 0050) ------------------------------------------------------

    /** Usage counters ({@code auth.counters}) and the zone of Login-Time and counter periods. */
    void limits(UsageCounters counters, java.time.ZoneId zone) {
        restrictions.limits(counters, zone);
    }

    void pools(IpPools pools) {
        addresses.pools(pools);
    }

    /** The zone of dates without one; set with the usage counters. */
    private java.time.ZoneId zone() {
        return restrictions.zone();
    }

    // ---- TOTP second factor (ADR 0053) -----------------------------------------------------------------------

    private final TotpFactor totp;
    private final PasswordChecks passwordChecks;
    private final InnerCredentials inner;
    private final Restrictions restrictions;
    private final AddressAssignment addresses = new AddressAssignment(once);
    static final String SIMULTANEOUS_USE = "Simultaneous-Use";

    void totp(Totp settings) {
        totp.settings(settings);
    }

    /** The PAP password: the decrypted User-Password, or what TOTP's append mode left of it; {@code null}: none. */
    byte[] papPassword(AuthRequest auth) {
        AccessContext context = auth.context();
        byte[] override = auth.papPassword;
        if (override != null) {
            return override.clone();
        }
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
        int n = context.credentials()
                .decryptUserPassword(context.request(), context.nas().secret(), buffer, 0);
        if (n < 0) {
            return null;
        }
        byte[] password = Arrays.copyOf(buffer.byteArray(), n);
        Arrays.fill(buffer.byteArray(), (byte) 0);
        return password;
    }

    // ---- SIM subscribers (ADR 0061) ------------------------------------------------------------------------------

    /** A SIM subscriber's check items by IMSI, from the stores of this NAS entry; keys are checked here once. */
    private EapMethod.Subscriber simSubscriber(AuthRequest auth, String imsi) {
        AccessContext context = auth.context();
        UserDirectory.Found found;
        try {
            found = directory.find(auth.caches(), context.nas().name(), imsi);
        } catch (StoreUnavailableException e) {
            warnOnce("unavailable:" + e.getMessage(), "identity store unavailable, requests are not answered: {}", e);
            because(context, "identity store unavailable: ", e.getMessage());
            return new EapMethod.Subscriber(DROP, List.of());
        }
        if (found == null) {
            because(context, "SIM subscriber not in any store: ", imsi);
            return new EapMethod.Subscriber(REJECT, List.of());
        }
        try {
            if (!SimSubscriber.of(found.user().check()).gsm()) {
                warnOnce(
                        "sim-keys:" + found.store(),
                        "store {}: SIM subscribers need SIM-Ki and SIM-OPc (or "
                                + "SIM-OP), or three stored triplets; COMP128 is not supported",
                        found.store());
                because(context, "no usable SIM keys for ", imsi);
                return new EapMethod.Subscriber(REJECT, List.of());
            }
        } catch (IllegalArgumentException e) {
            warnOnce("sim-keys-bad:" + found.store(), "store {}: {}", found.store(), e.getMessage()); // never the value
            because(context, "SIM keys not understood for ", imsi);
            return new EapMethod.Subscriber(REJECT, List.of());
        }
        return new EapMethod.Subscriber(ACCEPT, found.user().check());
    }

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

    // ---- Chargeable-User-Identity (ADR 0056) -------------------------------------------------------------------

    private volatile Cui cui;

    void cui(Cui cui) {
        this.cui = cui;
    }

    // ---- rules (ADR 0051) ---------------------------------------------------------------------------------------

    private volatile RulesFile rules;

    void rules(RulesFile rules) {
        this.rules = rules;
    }

    private Rules.Request ruleRequest(RadiusPacket request, UserRecord user) {
        return new Rules.Request() {
            @Override
            public String value(String attribute) {
                AttributeDef def = dictionary.find(attribute);
                if (def == null || def.vendorId() != 0) {
                    return null;
                }
                int at = request.findAttribute(def.number());
                return at < 0
                        ? null
                        : AttributeText.decode(
                                def, request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
            }

            @Override
            public boolean inGroup(String group) {
                for (UserRecord.Group g : user.groups()) {
                    if (g.name().equalsIgnoreCase(group)
                            && checkItems.checks(g.check(), request, new ArrayList<>()) != null) {
                        return true;
                    }
                }
                return false;
            }
        };
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
    public void writeMetrics(PrometheusWriter w, String gateway) {
        replies.writeMetrics(w, gateway);
        metrics.write(w, gateway, stores);
    }

    /** The reply items' encoder and its counters. */
    ReplyEncoder replies() {
        return replies;
    }

    /** Store look-ups and EAP outcomes. */
    AuthMetrics metrics() {
        return metrics;
    }

    private static String string(RadiusPacket request, int type) {
        int at = request.findAttribute(type);
        if (at < 0) {
            return null;
        }
        return request.buffer()
                .getStringWithoutLengthUtf8(at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
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
