/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.AttributeText;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.agrona.collections.IntHashSet;
import org.agrona.collections.Object2LongHashMap;
import org.agrona.collections.Object2ObjectHashMap;
import org.agrona.collections.ObjectHashSet;
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
    private static final Set<String> COMPARISONS = Set.of("==", "!=", "=~", "!~", "<", ">", "<=", ">=");
    private static final DateTimeFormatter[] DATES = {
        DateTimeFormatter.ofPattern("MMM d yyyy HH:mm:ss", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("MMM d yyyy HH:mm", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("d MMM yyyy HH:mm:ss", Locale.ENGLISH)
    };
    private static final DateTimeFormatter[] DAYS = {
        DateTimeFormatter.ofPattern("MMM d yyyy", Locale.ENGLISH),
        DateTimeFormatter.ofPattern("d MMM yyyy", Locale.ENGLISH)
    };

    private volatile AuthStores stores; // replaced by a reload (ADR 0054)
    private final Dictionary dictionary;
    private final LongSupplier clockMillis;
    private volatile long ttlMillis;
    private final ObjectHashSet<String> warned = new ObjectHashSet<>();
    /** Per NAS entry with a vendor filter; replaced as a whole by a reload, otherwise only read. */
    private volatile Map<String, AtomicLong> filtered = Map.of();
    /** Raised by a reload: workers then drop their caches. */
    private volatile int generation;

    private final byte[] verifierSalt = new byte[16];

    private record Cached(Optional<UserRecord> user, long expires) {}

    private record Found(String store, UserRecord user) {}

    /**
     * The caches of one worker, kept in its {@link AccessContext#handlerState()}: only that worker's thread touches
     * them, so they are plain Agrona maps without locks. A user's look-up is cached per worker (at most one look-up
     * per worker and TTL); each map is bounded by {@code auth.cache.max}.
     */
    private static final class WorkerCache {
        final Object2ObjectHashMap<String, Cached> users = new Object2ObjectHashMap<>();
        final Object2LongHashMap<String> verified = new Object2LongHashMap<>(Long.MIN_VALUE);
        final Object2ObjectHashMap<AttributeItem, Encoded> encoded = new Object2ObjectHashMap<>();
        final MsChapOutcome msChap = new MsChapOutcome();
        final EapRound eap = new EapRound();
        /** What TOTP's append mode left of the PAP password (ADR 0053); {@code null}: the User-Password. */
        byte[] papPassword;
        /** The handler's generation the caches belong to (ADR 0054). */
        int generation;
    }

    /** The EAP state of the request being decided; per worker, reset for every request. */
    private static final class EapRound {
        EapPacket packet;
        EapConversations.Conversation conversation;
        byte[] state;
        byte[] msk;

        void reset() {
            packet = null;
            state = null;
            conversation = null;
            msk = null;
        }
    }

    /** What a successful MS-CHAP check leaves for the reply; per worker, reset for every request. */
    private static final class MsChapOutcome {
        boolean success;
        int ident;
        byte[] ntHashHash;
        byte[] ntResponse;
        byte[] challengeHash;

        void reset() {
            success = false;
            ntHashHash = null;
            ntResponse = null;
            challengeHash = null;
        }
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
        this.ttlMillis = stores.cacheTtl().toMillis();
        new java.security.SecureRandom().nextBytes(verifierSalt);
        this.filtered = counters(stores, Map.of());
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
        cache.msChap.reset();
        cache.eap.reset();
        int result;
        try {
            result = decide(context, method);
        } finally {
            if (cache.papPassword != null) {
                Arrays.fill(cache.papPassword, (byte) 0);
                cache.papPassword = null;
            }
        }
        if (result == REJECT && isMsChap(method)) {
            writeMsChapError(context, method); // the client shows a proper failure instead of a timeout
        }
        if (result == REJECT && method == AccessRequests.METHOD_EAP && cache.eap.packet != null) {
            EapPacket.failure(cache.eap.packet.identifier()).writeTo(context.reply()); // RFC 3579 §2.6.3
        }
        return result;
    }

    private static boolean isMsChap(int method) {
        return method == AccessRequests.METHOD_MS_CHAP || method == AccessRequests.METHOD_MS_CHAP2;
    }

    private int decide(AccessContext context, int method) {
        RadiusPacket request = context.request();
        if (method != AccessRequests.METHOD_PAP
                && method != AccessRequests.METHOD_CHAP
                && !isMsChap(method)
                && method != AccessRequests.METHOD_EAP) {
            return REJECT; // none or several methods are never valid
        }
        String userName;
        if (method == AccessRequests.METHOD_EAP) {
            int begun = eapBegin(context);
            if (begun != ACCEPT) {
                return begun;
            }
            userName = cache(context).eap.conversation.identity;
        } else {
            userName = string(request, USER_NAME);
        }
        if (userName == null || userName.isEmpty()) {
            return REJECT;
        }
        Authorization a = authorize(context, userName, method == AccessRequests.METHOD_EAP && outerOptional(context));
        if (a.code() != ACCEPT) {
            return a.code();
        }
        Found found = a.found();
        String authType = a.authType();
        List<AttributeItem> passwords = a.passwords();
        if (method == AccessRequests.METHOD_EAP) {
            int round = eapRound(context, found, authType, passwords);
            if (round != ACCEPT) {
                return round; // CHALLENGE (another round trip), REJECT or DROP
            }
            EapConversations.Conversation c = cache(context).eap.conversation;
            String inner = c.method == null ? null : c.method.innerIdentity();
            InnerProxy p = innerProxy;
            if (inner != null && p != null && p.realm(inner) != null) {
                // the inner user's home server decided and authorized it (ADR 0044); its reply is ours
                if (c.proxiedReply == null) {
                    return REJECT; // no verdict from it in this conversation
                }
                writeEapSuccess(context, method);
                context.reply().rawAttributes(new UnsafeBuffer(c.proxiedReply), 0, c.proxiedReply.length);
                return ACCEPT;
            }
            if (inner != null) { // a tunnel: the inner user is the one authorized (ADR 0029)
                a = authorize(context, inner, c.method.innerOptional());
                if (a.code() != ACCEPT) {
                    return a.code();
                }
                found = a.found();
            }
        } else {
            boolean firstFactor = !authType.equalsIgnoreCase("Accept");
            boolean challenge = false;
            String secret = totpSecret(a);
            if (secret != null) {
                int second = totp(context, method, userName, secret);
                if (second == TOTP_CODE_OK) {
                    firstFactor = false; // the password was checked in the round that asked for the code
                } else if (second == TOTP_ASK) {
                    challenge = true;
                } else if (second != ACCEPT) {
                    return second;
                }
            }
            if (firstFactor) {
                String verifier = verifierFor(authType, found.store(), passwords);
                int checked = verifier != null
                        ? verify(context, method, verifier, userName)
                        : authenticate(context, method, found, userName, passwords) ? ACCEPT : REJECT;
                if (checked != ACCEPT) {
                    return checked;
                }
            }
            if (challenge) {
                return totpChallenge(context, userName);
            }
        }
        if (a.limit() != null) {
            int decision = limit(context, request, found.store(), a.limit());
            if (decision != ACCEPT) {
                because(context, "Simultaneous-Use not granted: ", a.limit());
                return decision;
            }
        }
        int restricted = restrict(context, found.user().userName(), a);
        if (restricted != ACCEPT) {
            return restricted;
        }
        int pooled = assignAddress(context, request, found.user().userName(), a);
        if (pooled != ACCEPT) {
            return pooled;
        }
        RulesFile r = rules;
        if (r != null && !r.current().apply(ruleRequest(request, found.user()), a.reply())) {
            because(context, "rejected by a rule of ", "auth.rules");
            return REJECT;
        }
        encode(cache(context).encoded, a.reply(), context.reply(), context.nas().name());
        writeMsChapSuccess(context, method); // method attributes: never filtered by vendor
        writeEapSuccess(context, method);
        return ACCEPT;
    }

    /**
     * The authorization of a user: its store entry, check items and the groups that apply. {@code code} is
     * {@link #ACCEPT} to go on, {@link #REJECT} (unknown user, failed check, Auth-Type Reject) or {@link #DROP}.
     */
    private record Authorization(
            int code,
            Found found,
            String authType,
            List<AttributeItem> passwords,
            List<AttributeItem> reply,
            String limit,
            List<AttributeItem> restrictions) {

        static Authorization of(int code) {
            return new Authorization(code, null, null, null, null, null, List.of());
        }
    }

    /**
     * What the store sweep learns about a user with active sessions (ADR 0036).
     *
     * @param code {@link #ACCEPT} (still let in), {@link #REJECT} (rejected now: disabled, or {@code Auth-Type :=
     *     Reject}), {@link #DROP} (no store answered); {@code found}: whether a store has the user
     * @param reply the reply items the user would get now, for the NAS entry's vendors
     */
    record Review(int code, boolean found, List<AttributeItem> reply) {}

    private final AccessContext sweepContext = new AccessContext();
    private final UnsafeBuffer sweepRequest = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);

    /**
     * Looks a user with active sessions up again, as at login: its checks and groups evaluated against a request
     * made of the session's identifying attributes (conditions on other attributes do not match). One caller at a
     * time: the sweep has its own context and caches.
     */
    synchronized Review review(NasClient nas, String userName, byte[] identity) {
        int length = RadiusPacket.HEADER_LENGTH + identity.length;
        sweepRequest.putByte(0, (byte) io.radiusward.radius.codec.RadiusCode.ACCESS_REQUEST);
        sweepRequest.putByte(1, (byte) 0);
        sweepRequest.putShort(2, (short) length, java.nio.ByteOrder.BIG_ENDIAN);
        sweepRequest.setMemory(4, 16, (byte) 0);
        sweepRequest.putBytes(RadiusPacket.HEADER_LENGTH, identity);
        sweepContext.reset(sweepRequest, 0, length, nas);
        Found found;
        try {
            found = find(cache(sweepContext), nas.name(), userName);
        } catch (StoreUnavailableException e) {
            return new Review(DROP, false, List.of());
        }
        if (found == null) {
            return new Review(REJECT, false, List.of());
        }
        Authorization a = authorize(sweepContext, userName, false);
        if (a.code() != ACCEPT) {
            return new Review(a.code(), true, List.of());
        }
        IntHashSet vendors = stores.replyVendors().get(nas.name());
        List<AttributeItem> reply = new ArrayList<>();
        for (AttributeItem item : a.reply()) {
            AttributeDef def = dictionary.find(item.attribute());
            if (def != null && (def.vendorId() == 0 || vendors == null || vendors.contains(def.vendorId()))) {
                reply.add(item);
            }
        }
        return new Review(ACCEPT, true, reply);
    }

    /** Looks {@code userName} up and evaluates its checks and groups; {@code optional}: a missing user is empty. */
    private Authorization authorize(AccessContext context, String userName, boolean optional) {
        RadiusPacket request = context.request();
        Found found;
        try {
            found = find(cache(context), context.nas().name(), userName);
        } catch (StoreUnavailableException e) {
            warnOnce("unavailable:" + e.getMessage(), "identity store unavailable, requests are not answered: {}", e);
            because(context, "identity store unavailable: ", e.getMessage());
            return Authorization.of(DROP);
        }
        if (found == null) {
            if (!optional) {
                because(context, "user not in any store: ", userName);
                return Authorization.of(REJECT);
            }
            // EAP-TLS: the certificate is the credential; tunnels: the inner user is looked up (ADR 0028, 0029)
            found = new Found("", new UserRecord(userName, List.of(), List.of(), List.of()));
        }
        List<AttributeItem> passwords = new ArrayList<>();
        List<AttributeItem> reply = new ArrayList<>(found.user().reply());
        note(
                context,
                "user found in store ",
                found.store().isEmpty() ? "(none, certificate or tunnel)" : found.store());
        String authType = checks(found.user().check(), request, passwords);
        if (authType == null) {
            because(context, "a check item of the user does not hold (Expiration or a comparison)", "");
            return Authorization.of(REJECT);
        }
        String limit = simultaneousUse(found.user().check());
        for (UserRecord.Group group : found.user().groups()) {
            List<AttributeItem> groupPasswords = new ArrayList<>();
            String groupAuthType = checks(group.check(), request, groupPasswords);
            if (groupAuthType == null) {
                note(context, "group does not apply: ", group.name());
                continue; // the group's conditions do not hold: it does not apply
            }
            note(context, "group applies: ", group.name());
            if (groupAuthType.equalsIgnoreCase("Reject")) {
                because(context, "Auth-Type := Reject in group ", group.name());
                return Authorization.of(REJECT);
            }
            if (authType.isEmpty()) {
                authType = groupAuthType;
            }
            if (limit == null) {
                limit = simultaneousUse(group.check()); // the user's own limit wins, then the first group's
            }
            passwords.addAll(groupPasswords);
            merge(reply, group.reply());
        }
        if (authType.equalsIgnoreCase("Reject")) {
            because(context, "Auth-Type := Reject", "");
            return Authorization.of(REJECT);
        }
        if (!authType.isEmpty()) {
            note(context, "Auth-Type: ", authType);
        }
        List<AttributeItem> restrictions = new ArrayList<>();
        collectRestrictions(found.user().check(), restrictions);
        for (UserRecord.Group group : found.user().groups()) {
            if (checks(group.check(), request, new ArrayList<>()) != null) {
                collectRestrictions(group.check(), restrictions);
            }
        }
        return new Authorization(ACCEPT, found, authType, passwords, reply, limit, restrictions);
    }

    // ---- look-up -------------------------------------------------------------------------------

    private Found find(WorkerCache cache, String nas, String userName) throws StoreUnavailableException {
        Object2ObjectHashMap<String, Cached> users = cache.users;
        StoreUnavailableException unavailable = null;
        long now = clockMillis.getAsLong();
        for (String name : stores.storesFor(nas)) {
            String key = name + '\0' + userName;
            Cached cached = users.get(key);
            Optional<UserRecord> user;
            if (cached != null && cached.expires() - now > 0) {
                user = cached.user();
            } else {
                IdentityStore store = stores.stores().get(name);
                try {
                    user = store.lookup(userName);
                } catch (StoreUnavailableException e) {
                    unavailable = e;
                    continue;
                }
                if (ttlMillis > 0) {
                    if (users.size() >= stores.cacheMax()) {
                        users.clear(); // simple bound; a reconnect storm refills it within one TTL
                    }
                    users.put(key, new Cached(user, now + ttlMillis));
                }
            }
            if (user.isPresent()) {
                return new Found(name, user.get());
            }
        }
        if (unavailable != null) {
            throw unavailable; // a store that is down might know the user: do not reject on its behalf
        }
        return null;
    }

    // ---- check items -------------------------------------------------------------------------

    /**
     * Evaluates check items; collects passwords.
     *
     * @return the {@code Auth-Type} ("" if none), or {@code null} if a condition fails
     */
    private String checks(List<AttributeItem> items, RadiusPacket request, List<AttributeItem> passwords) {
        String authType = "";
        for (AttributeItem item : items) {
            String name = item.attribute();
            if (PasswordCheck.isPassword(name)
                    || name.equalsIgnoreCase("NT-Password")
                    || name.equalsIgnoreCase("LM-Password")) {
                passwords.add(item);
            } else if (name.equalsIgnoreCase("Auth-Type")) {
                authType = item.value();
            } else if (name.equalsIgnoreCase("Expiration")) {
                Instant expires = date(item.value());
                if (expires == null
                        || !Instant.ofEpochMilli(clockMillis.getAsLong()).isBefore(expires)) {
                    return null;
                }
            } else if (name.equalsIgnoreCase(SIMULTANEOUS_USE)) {
                continue; // applied after authentication, through the cluster (#limit)
            } else if (COMPARISONS.contains(item.op()) && !compare(item, request)) {
                return null;
            }
            // other ':=', '=', '+=' items are configuration items without meaning here
        }
        return authType;
    }

    private boolean compare(AttributeItem item, RadiusPacket request) {
        AttributeDef def = dictionary.find(item.attribute());
        if (def == null || def.vendorId() != 0) {
            warnOnce(
                    "compare:" + item.attribute(),
                    "check item {} cannot be compared (unknown or vendor-specific):" + " the condition fails",
                    item.attribute());
            return false;
        }
        int at = request.findAttribute(def.number());
        String actual = at < 0
                ? null
                : AttributeText.decode(
                        def, request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
        String expected = item.value();
        try {
            return switch (item.op()) {
                case "==" -> expected.equals(actual);
                case "!=" -> !expected.equals(actual);
                case "=~" ->
                    actual != null && Pattern.compile(expected).matcher(actual).find();
                case "!~" ->
                    actual == null || !Pattern.compile(expected).matcher(actual).find();
                default -> numeric(item.op(), actual, expected);
            };
        } catch (PatternSyntaxException e) {
            warnOnce("regex:" + expected, "check item {}: invalid pattern, the condition fails", item.attribute());
            return false;
        }
    }

    private static boolean numeric(String op, String actual, String expected) {
        try {
            long a = Long.parseLong(actual);
            long e = Long.parseLong(expected);
            return switch (op) {
                case "<" -> a < e;
                case ">" -> a > e;
                case "<=" -> a <= e;
                default -> a >= e;
            };
        } catch (NumberFormatException | NullPointerException ex) {
            return false;
        }
    }

    private Instant date(String text) {
        String t = text.trim().replaceAll("\\s+", " ");
        try {
            return Instant.parse(t);
        } catch (DateTimeParseException ignored) {
            // not ISO-8601
        }
        for (DateTimeFormatter f : DATES) {
            try {
                return LocalDateTime.parse(t, f).atZone(zone).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        for (DateTimeFormatter f : DAYS) {
            try {
                return LocalDate.parse(t, f).atStartOfDay(zone).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        try {
            return LocalDate.parse(t).atStartOfDay(zone).toInstant();
        } catch (DateTimeParseException e) {
            return null; // fail closed
        }
    }

    // ---- EAP (RFC 3748, RFC 3579; ADR 0026) -----------------------------------------------------

    private static final int STATE = 24;

    /**
     * Reads the EAP response and finds its conversation: a new one for an Identity response without State, the one
     * the State names otherwise. {@link #ACCEPT} to go on; a malformed packet is discarded ({@link #DROP}), an
     * unknown or used State is rejected.
     */
    private int eapBegin(AccessContext context) {
        RadiusPacket request = context.request();
        EapPacket eap = EapPacket.from(request);
        if (eap == null || eap.code() != EapPacket.RESPONSE) {
            return DROP; // RFC 3579 §2.6.2: silently discard
        }
        EapRound round = cache(context).eap;
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
    private int eapRound(AccessContext context, Found found, String authType, List<AttributeItem> passwords) {
        EapRound round = cache(context).eap;
        EapPacket eap = round.packet;
        EapConversations.Conversation c = round.conversation;
        if (authType.equalsIgnoreCase("Accept")) {
            return ACCEPT; // no credential to check: EAP-Success right away
        }
        EapMethod.Credentials credentials = new EapMethod.Credentials(
                passwords, stores.chap().getOrDefault(found.store(), false), new EapMethod.InnerAuth() {
                    @Override
                    public EapMethod.Inner msChapV2(String user, EapMethod.MsChapV2 exchange) {
                        InnerProxy p = innerProxy;
                        if (p != null && p.realm(user) != null) {
                            return proxied(context, p.msChapV2(user, exchange));
                        }
                        return innerMsChapV2(context, user, exchange.challengeHash(), exchange.ntResponse());
                    }

                    @Override
                    public EapMethod.Inner password(String user, byte[] password) {
                        return innerPassword(context, user, password);
                    }

                    @Override
                    public EapMethod.Inner chap(String user, int identifier, byte[] challenge, byte[] response) {
                        return innerChap(context, user, identifier, challenge, response);
                    }

                    @Override
                    public EapMethod.Inner msChapV1(String user, byte[] challenge, byte[] ntResponse) {
                        return innerMsChap(context, user, challenge, ntResponse, false);
                    }
                });
        EapMethod.Step step;
        if (c.method == null) {
            c.method = stores.eap().create(EapConfig.type(stores.eap().methods().get(0)), c.identity);
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
            // the inner credential cannot be checked now: keep the conversation for the peer's retransmission
            if (round.state != null) {
                conversations.putBack(round.state, c, clockMillis.getAsLong());
            }
            return DROP;
        }
        if (++c.rounds > stores.eap().maxRounds()) {
            return REJECT;
        }
        if (step.done()) {
            round.msk = step.msk();
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
    private boolean outerOptional(AccessContext context) {
        EapRound round = cache(context).eap;
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
    private void writeEapSuccess(AccessContext context, int method) {
        EapRound round = cache(context).eap;
        if (method != AccessRequests.METHOD_EAP || round.packet == null) {
            return;
        }
        EapPacket.success(round.packet.identifier()).writeTo(context.reply());
        if (round.msk != null && round.msk.length >= 64) {
            byte[] authenticator = new byte[16];
            context.request().buffer().getBytes(context.request().authenticatorOffset(), authenticator);
            byte[] secret = context.nas().secret();
            int salt = saltRandom.nextInt(0x8000) & ~1;
            context.reply()
                    .vendorAttribute(
                            MICROSOFT,
                            MS_MPPE_RECV_KEY,
                            MsChap.encryptKey(Arrays.copyOfRange(round.msk, 0, 32), secret, authenticator, salt(salt)));
            context.reply()
                    .vendorAttribute(
                            MICROSOFT,
                            MS_MPPE_SEND_KEY,
                            MsChap.encryptKey(
                                    Arrays.copyOfRange(round.msk, 32, 64), secret, authenticator, salt(salt | 1)));
        }
    }

    /** Conversations in the table (for {@code /state} and tests). */
    int eapConversations() {
        return conversations.size();
    }

    // ---- MS-CHAP (RFC 2433, RFC 2759, RFC 2548, RFC 3079) ---------------------------------------

    private static final int MICROSOFT = 311;
    private static final int MS_CHAP_RESPONSE = 1;
    private static final int MS_CHAP_ERROR = 2;
    private static final int MS_CHAP_CHALLENGE = 11;
    private static final int MS_CHAP_MPPE_KEYS = 12;
    private static final int MS_MPPE_SEND_KEY = 16;
    private static final int MS_MPPE_RECV_KEY = 17;
    private static final int MS_CHAP2_RESPONSE = 25;
    private static final int MS_CHAP2_SUCCESS = 26;
    private static final int RESPONSE_LENGTH = 50;

    private final java.security.SecureRandom saltRandom = new java.security.SecureRandom();
    private final EapConversations conversations;

    /**
     * Verifies MS-CHAPv1 or v2 from the user's NT hash: {@code NT-Password}, or the cleartext password where the
     * store allows it ({@code auth.store.<name>.mschap}). The first usable credential decides.
     */
    private boolean msChap(AccessContext context, int method, Found found, List<AttributeItem> passwords) {
        byte[] ntHash = localNtHash(found, passwords);
        if (ntHash == null) {
            return false;
        }
        MsChapRequest r = msChapRequest(context.request(), method);
        if (r == null
                || !java.security.MessageDigest.isEqual(
                        MsChap.challengeResponse(r.challenge(), ntHash), r.ntResponse())) {
            return false;
        }
        succeeded(context, r, Md4.digest(ntHash));
        return true;
    }

    /** The user's NT hash from its store: NT-Password, or the cleartext where the store allows it; {@code null}. */
    private byte[] localNtHash(Found found, List<AttributeItem> passwords) {
        for (AttributeItem p : passwords) {
            if (p.attribute().equalsIgnoreCase("NT-Password")) {
                byte[] ntHash = MsChap.parseNtPassword(p.value());
                if (ntHash == null) {
                    warnOnce(
                            "nt-password:" + found.store(),
                            "store {}: NT-Password is not 32 hex digits; such users are rejected",
                            found.store());
                }
                return ntHash;
            }
            if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT)
                    && stores.mschap().getOrDefault(found.store(), false)) {
                return MsChap.ntHash(p.value());
            }
        }
        warnOnce(
                "mschap:" + found.store(),
                "MS-CHAP request for store {} without NT-Password (or Cleartext-Password with"
                        + " auth.store.<name>.mschap = true): rejected",
                found.store());
        return null;
    }

    // ---- time and usage restrictions (ADR 0049) ---------------------------------------------------------------

    private volatile UsageCounters counters;
    private volatile java.time.ZoneId zone = java.time.ZoneId.systemDefault();

    /** Usage counters ({@code auth.counters}) and the zone of Login-Time and counter periods. */
    void limits(UsageCounters counters, java.time.ZoneId zone) {
        this.counters = counters;
        this.zone = zone;
    }

    private void collectRestrictions(List<AttributeItem> checks, List<AttributeItem> into) {
        UsageCounters c = counters;
        for (AttributeItem item : checks) {
            String name = item.attribute();
            if (name.equalsIgnoreCase("Expiration")
                    || name.equalsIgnoreCase("Login-Time")
                    || name.equalsIgnoreCase("Pool-Name")
                    || name.equalsIgnoreCase(TOTP_SECRET)) {
                into.add(item);
            } else if (c != null
                    && c.counters().stream().anyMatch(k -> k.check().equalsIgnoreCase(name))) {
                into.add(item);
            }
        }
    }

    /**
     * Expiration, Login-Time and usage counters of the authorized user: outside a login window or over a limit is a
     * reject; otherwise the Accept's Session-Timeout is cut to the earliest end (expiry, the window's end, the time
     * left on a time counter or its period). A counter that cannot be read leaves the request unanswered.
     */
    private int restrict(AccessContext context, String user, Authorization a) {
        if (a.restrictions().isEmpty()) {
            return ACCEPT;
        }
        Instant now = Instant.ofEpochMilli(clockMillis.getAsLong());
        java.time.ZonedDateTime local = now.atZone(zone);
        long cap = Long.MAX_VALUE;
        for (AttributeItem item : a.restrictions()) {
            String name = item.attribute();
            if (name.equalsIgnoreCase("Expiration")) {
                Instant expires = date(item.value());
                if (expires == null || !now.isBefore(expires)) {
                    because(context, "expired: ", item.value());
                    return REJECT;
                }
                cap = Math.min(
                        cap,
                        Math.max(1, java.time.Duration.between(now, expires).getSeconds()));
            } else if (name.equalsIgnoreCase("Pool-Name") || name.equalsIgnoreCase(TOTP_SECRET)) {
                continue; // #assignAddress, #totp
            } else if (name.equalsIgnoreCase("Login-Time")) {
                LoginTime window = LoginTime.parse(item.value());
                if (window == null) {
                    warnOnce(
                            "login-time:" + item.value(),
                            "Login-Time {}: not understood, the user is rejected",
                            item.value());
                    because(context, "Login-Time not understood: ", item.value());
                    return REJECT;
                }
                long left = window.secondsLeft(local);
                if (left < 0) {
                    because(context, "outside Login-Time ", item.value());
                    return REJECT;
                }
                cap = Math.min(cap, Math.max(1, left));
            } else {
                for (UsageCounters.Counter counter : counters.counters()) {
                    if (!counter.check().equalsIgnoreCase(name)) {
                        continue;
                    }
                    long limit;
                    try {
                        limit = Long.parseLong(item.value().trim());
                    } catch (NumberFormatException e) {
                        warnOnce("counter:" + name, "{}: {} is not a number, the user is rejected", name, item.value());
                        because(context, name + " is not a number: ", item.value());
                        return REJECT;
                    }
                    long used;
                    try {
                        used = counters.usage(counter, user, UsageCounters.periodStart(counter.reset(), local));
                    } catch (Exception e) {
                        warnOnce(
                                "counter-unavailable:" + counter.name(),
                                "usage counter {} unavailable, requests are not answered: {}",
                                counter.name(),
                                e.toString());
                        because(context, "usage counter unavailable: ", counter.name());
                        return DROP;
                    }
                    note(context, counter.name() + ": used " + used + " of ", item.value());
                    if (used >= limit) {
                        because(context, "usage limit reached: ", counter.name());
                        return REJECT;
                    }
                    if (counter.kind() == UsageCounters.Kind.TIME) {
                        cap = Math.min(cap, limit - used);
                        Instant end = UsageCounters.periodEnd(counter.reset(), local);
                        if (end != null) {
                            cap = Math.min(
                                    cap,
                                    Math.max(
                                            1,
                                            java.time.Duration.between(now, end).getSeconds()));
                        }
                    } else if (counter.reply() != null) {
                        replace(a.reply(), counter.reply(), Long.toString(limit - used));
                    }
                }
            }
        }
        if (cap != Long.MAX_VALUE) {
            long timeout = cap;
            for (AttributeItem r : a.reply()) {
                if (r.attribute().equalsIgnoreCase("Session-Timeout")) {
                    try {
                        timeout = Math.min(timeout, Long.parseLong(r.value().trim()));
                    } catch (NumberFormatException e) {
                        // a malformed value is replaced
                    }
                }
            }
            replace(a.reply(), "Session-Timeout", Long.toString(Math.min(timeout, 0xFFFFFFFFL)));
            note(context, "Session-Timeout capped to ", Long.toString(Math.min(timeout, 0xFFFFFFFFL)));
        }
        return ACCEPT;
    }

    // ---- TOTP second factor (ADR 0053) -----------------------------------------------------------------------

    static final String TOTP_SECRET = "TOTP-Secret";
    private static final int REPLY_MESSAGE = 18;
    /** {@link #totp}: the code of a challenge was right; the password was checked before. */
    private static final int TOTP_CODE_OK = -1;
    /** {@link #totp}: check the password, then ask for the code. */
    private static final int TOTP_ASK = -2;

    private static final int MAX_CHALLENGES = 10_000;

    private record Pending(String user, long expiresMillis) {}

    private volatile Totp totp = Totp.DEFAULT;
    private final java.util.concurrent.ConcurrentHashMap<String, Pending> challenges =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** The last time step used per user: a code is accepted once. */
    private final java.util.concurrent.ConcurrentHashMap<String, Long> usedSteps =
            new java.util.concurrent.ConcurrentHashMap<>();

    void totp(Totp totp) {
        this.totp = totp;
    }

    private static String totpSecret(Authorization a) {
        for (AttributeItem item : a.restrictions()) {
            if (item.attribute().equalsIgnoreCase(TOTP_SECRET)) {
                return item.value();
            }
        }
        return null;
    }

    /** The PAP password: the decrypted User-Password, or what TOTP's append mode left of it; {@code null}: none. */
    private byte[] papPassword(AccessContext context) {
        byte[] override = cache(context).papPassword;
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

    /**
     * The second factor of a user with a TOTP secret: {@link #ACCEPT} (append mode: the code was right, the password
     * remains to be checked), {@link #TOTP_CODE_OK}, {@link #TOTP_ASK}, or {@link #REJECT}.
     */
    private int totp(AccessContext context, int method, String userName, String secret) {
        Totp t = totp;
        if (method != AccessRequests.METHOD_PAP) {
            warnOnce("totp:" + method, "users with a TOTP-Secret need PAP; {} is rejected", methodName(method));
            because(context, "TOTP needs PAP", "");
            return REJECT;
        }
        byte[] key = Totp.base32(secret);
        if (key == null) {
            warnOnce("totp-secret:" + userName, "TOTP-Secret of user {} is not base32 of 10 bytes or more", userName);
            because(context, "TOTP-Secret not understood", "");
            return REJECT;
        }
        byte[] password = papPassword(context);
        if (password == null) {
            return REJECT;
        }
        try {
            if (t.append()) {
                if (password.length < t.digits()) {
                    because(context, "no TOTP code after the password", "");
                    return REJECT;
                }
                int split = password.length - t.digits();
                if (!codeAccepted(
                        context,
                        t,
                        key,
                        userName,
                        new String(password, split, t.digits(), StandardCharsets.US_ASCII))) {
                    return REJECT;
                }
                cache(context).papPassword = Arrays.copyOf(password, split);
                return ACCEPT;
            }
            RadiusPacket request = context.request();
            int at = request.findAttribute(STATE);
            Pending pending = null;
            if (at >= 0) {
                pending = challenges.remove(
                        stateKey(request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2));
            }
            if (pending == null) {
                return TOTP_ASK;
            }
            if (!pending.user().equals(userName) || pending.expiresMillis() < clockMillis.getAsLong()) {
                because(context, "TOTP challenge expired or of another user", "");
                return REJECT;
            }
            return codeAccepted(context, t, key, userName, new String(password, StandardCharsets.US_ASCII))
                    ? TOTP_CODE_OK
                    : REJECT;
        } finally {
            Arrays.fill(password, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    private boolean codeAccepted(AccessContext context, Totp t, byte[] key, String userName, String code) {
        long step = t.match(key, code, clockMillis.getAsLong() / 1000);
        if (step < 0) {
            because(context, "wrong TOTP code", "");
            return false;
        }
        boolean[] fresh = {false};
        usedSteps.compute(userName, (u, last) -> {
            if (last != null && last >= step) {
                return last;
            }
            fresh[0] = true;
            return step;
        });
        if (!fresh[0]) {
            because(context, "TOTP code already used", "");
        }
        return fresh[0];
    }

    /** Asks for the code: an Access-Challenge with a fresh State and the prompt. */
    private int totpChallenge(AccessContext context, String userName) {
        long now = clockMillis.getAsLong();
        if (challenges.size() >= MAX_CHALLENGES) {
            challenges.values().removeIf(p -> p.expiresMillis() < now);
            if (challenges.size() >= MAX_CHALLENGES) {
                warnOnce("totp-full", "{} TOTP challenges open: further ones are not answered", MAX_CHALLENGES);
                return DROP;
            }
        }
        byte[] state = new byte[16];
        saltRandom.nextBytes(state);
        challenges.put(
                stateKey(new UnsafeBuffer(state), 0, state.length),
                new Pending(userName, now + totp.timeout().toMillis()));
        context.reply().attribute(STATE, state);
        context.reply().attribute(REPLY_MESSAGE, totp.prompt());
        note(context, "password right, TOTP code asked for", "");
        return CHALLENGE;
    }

    private static String stateKey(org.agrona.DirectBuffer buffer, int offset, int length) {
        return io.radiusward.radius.codec.AttributeValues.hex(buffer, offset, length);
    }

    // ---- traces (ADR 0052) ---------------------------------------------------------------------------------------

    private static void note(AccessContext context, String step, String detail) {
        Tracer.Trace trace = context.trace();
        if (trace != null) {
            trace.note(step + detail);
        }
    }

    private static void because(AccessContext context, String step, String detail) {
        Tracer.Trace trace = context.trace();
        if (trace != null) {
            trace.because(step + detail);
        }
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
                    if (g.name().equalsIgnoreCase(group) && checks(g.check(), request, new ArrayList<>()) != null) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    // ---- IP pools (ADR 0050) ------------------------------------------------------------------------------------

    private volatile IpPools pools;

    void pools(IpPools pools) {
        this.pools = pools;
    }

    /**
     * A {@code Framed-IP-Address} from the pool named by the user's (else a group's) {@code Pool-Name}, unless the
     * reply already has one. An empty pool rejects (or accepts without an address, per pool); a pool that cannot be
     * reached leaves the request unanswered.
     */
    private int assignAddress(AccessContext context, RadiusPacket request, String user, Authorization a) {
        String name = null;
        for (AttributeItem item : a.restrictions()) {
            if (item.attribute().equalsIgnoreCase("Pool-Name")) {
                name = item.value();
                break;
            }
        }
        if (name == null || a.reply().stream().anyMatch(r -> r.attribute().equalsIgnoreCase("Framed-IP-Address"))) {
            return ACCEPT;
        }
        IpPools p = pools;
        IpPools.Pool pool = p == null ? null : p.pool(name);
        if (pool == null) {
            warnOnce("pool:" + name, "Pool-Name {}: no such pool in auth.pools, the user is rejected", name);
            because(context, "no such pool: ", name);
            return REJECT;
        }
        int station = request.findAttribute(CALLING_STATION_ID);
        String device = station < 0
                ? user
                : request.buffer()
                        .getStringWithoutLengthUtf8(
                                station + 2, (request.buffer().getByte(station + 1) & 0xFF) - 2);
        String address;
        try {
            address = p.allocate(pool, user, device);
        } catch (Exception e) {
            warnOnce(
                    "pool-unavailable:" + pool.name(),
                    "IP pool {} unavailable, requests are not answered: {}",
                    pool.name(),
                    e.toString());
            because(context, "IP pool unavailable: ", pool.name());
            return DROP;
        }
        if (address == null) {
            warnOnce("pool-empty:" + pool.name(), "IP pool {} has no free address", pool.name());
            because(context, "IP pool has no free address: ", pool.name());
            return pool.exhausted() ? ACCEPT : REJECT;
        }
        note(context, "address from pool " + pool.name() + ": ", address);
        a.reply().add(new AttributeItem("Framed-IP-Address", "=", address));
        return ACCEPT;
    }

    private static void replace(List<AttributeItem> reply, String attribute, String value) {
        reply.removeIf(r -> r.attribute().equalsIgnoreCase(attribute));
        reply.add(new AttributeItem(attribute, "=", value));
    }

    /** Inner checks of proxied realms' users go to their home servers when set (ADR 0044). */
    private volatile InnerProxy innerProxy;

    void proxyInner(InnerProxy proxy) {
        this.innerProxy = proxy;
    }

    InnerProxy innerProxy() {
        return innerProxy;
    }

    /** A home server's verdict on the inner user: its reply kept for our Accept, the tunnel not remembered. */
    private EapMethod.Inner proxied(AccessContext context, InnerProxy.Result r) {
        EapConversations.Conversation c = cache(context).eap.conversation;
        if (c != null) {
            if (r.inner().code() == ACCEPT) {
                c.proxiedReply = r.reply();
            }
            if (c.method instanceof TlsTunnel tunnel) {
                tunnel.notResumable();
            }
        }
        return r.inner();
    }

    /**
     * MS-CHAPv2 inside a tunnel (PEAP, TTLS): the inner user is looked up and checked like outside — a credential
     * verifier, or the local NT hash.
     */
    private EapMethod.Inner innerMsChapV2(AccessContext context, String user, byte[] challengeHash, byte[] ntResponse) {
        return innerMsChap(context, user, challengeHash, ntResponse, true);
    }

    /**
     * CHAP inside a tunnel: only with the cleartext password of a store that allows CHAP, as outside it; verifiers
     * cannot answer CHAP.
     */
    private EapMethod.Inner innerChap(
            AccessContext context, String user, int identifier, byte[] challenge, byte[] response) {
        InnerProxy home = innerProxy;
        if (home != null && home.realm(user) != null) {
            return proxied(context, home.chap(user, identifier, challenge, response));
        }
        Authorization a = authorize(context, user, false);
        if (a.code() != ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        if (a.authType().equalsIgnoreCase("Accept")) {
            return new EapMethod.Inner(ACCEPT, null);
        }
        if (!stores.chap().getOrDefault(a.found().store(), false)) {
            warnOnce(
                    "chap:" + a.found().store(),
                    "CHAP request for store {}, which does not allow CHAP"
                            + " (auth.store.<name>.chap = true needs cleartext passwords): rejected",
                    a.found().store());
            return new EapMethod.Inner(REJECT, null);
        }
        for (AttributeItem p : a.passwords()) {
            if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT)) {
                byte[] clear = p.value().getBytes(StandardCharsets.UTF_8);
                try {
                    java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
                    md5.update((byte) identifier);
                    md5.update(clear);
                    md5.update(challenge);
                    return new EapMethod.Inner(
                            java.security.MessageDigest.isEqual(md5.digest(), response) ? ACCEPT : REJECT, null);
                } catch (java.security.NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                } finally {
                    Arrays.fill(clear, (byte) 0);
                }
            }
        }
        return new EapMethod.Inner(REJECT, null);
    }

    /** MS-CHAP inside a tunnel; {@code challenge} is the v2 challenge hash or the v1 challenge (both 8 bytes). */
    private EapMethod.Inner innerMsChap(
            AccessContext context, String user, byte[] challenge, byte[] ntResponse, boolean v2) {
        Authorization a = authorize(context, user, false);
        if (a.code() != ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        String verifier = verifierFor(a.authType(), a.found().store(), a.passwords());
        if (verifier != null) {
            try {
                CredentialVerifier.Result r =
                        stores.verifiers().get(verifier).verifyMsChap(user, challenge, ntResponse, v2);
                return r.accepted() && r.ntHashHash() != null
                        ? new EapMethod.Inner(ACCEPT, r.ntHashHash())
                        : new EapMethod.Inner(REJECT, null);
            } catch (StoreUnavailableException e) {
                warnOnce(
                        "verifier-unavailable:" + verifier + ":" + e.getMessage(),
                        "verifier {} unavailable, requests are not answered: {}",
                        verifier,
                        e.getMessage());
                return new EapMethod.Inner(DROP, null);
            }
        }
        byte[] ntHash = localNtHash(a.found(), a.passwords());
        if (ntHash == null
                || !java.security.MessageDigest.isEqual(MsChap.challengeResponse(challenge, ntHash), ntResponse)) {
            return new EapMethod.Inner(REJECT, null);
        }
        return new EapMethod.Inner(ACCEPT, Md4.digest(ntHash));
    }

    /** A password inside a tunnel (TTLS/PAP): the inner user looked up, then a verifier or the stored credentials. */
    private EapMethod.Inner innerPassword(AccessContext context, String user, byte[] password) {
        InnerProxy home = innerProxy;
        if (home != null && home.realm(user) != null) {
            return proxied(context, home.password(user, password));
        }
        Authorization a = authorize(context, user, false);
        if (a.code() != ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        if (a.authType().equalsIgnoreCase("Accept")) {
            return new EapMethod.Inner(ACCEPT, null);
        }
        String verifier = verifierFor(a.authType(), a.found().store(), a.passwords());
        if (verifier != null) {
            try {
                return new EapMethod.Inner(
                        stores.verifiers()
                                        .get(verifier)
                                        .verifyPassword(user, password)
                                        .accepted()
                                ? ACCEPT
                                : REJECT,
                        null);
            } catch (StoreUnavailableException e) {
                warnOnce(
                        "verifier-unavailable:" + verifier + ":" + e.getMessage(),
                        "verifier {} unavailable, requests are not answered: {}",
                        verifier,
                        e.getMessage());
                return new EapMethod.Inner(DROP, null);
            }
        }
        return new EapMethod.Inner(
                checkPassword(context, a.found(), user, a.passwords(), password) ? ACCEPT : REJECT, null);
    }

    /**
     * The parts of an MS-CHAP request a check needs: the 8-byte challenge the NT response answers (v2: the challenge
     * hash), the response, its ident; {@code null} if malformed.
     */
    private record MsChapRequest(byte[] challenge, byte[] ntResponse, int ident, byte[] challengeHash, boolean v2) {}

    private static MsChapRequest msChapRequest(RadiusPacket request, int method) {
        byte[] challenge = vendorValue(request, MS_CHAP_CHALLENGE);
        boolean v2 = method == AccessRequests.METHOD_MS_CHAP2;
        byte[] response = vendorValue(request, v2 ? MS_CHAP2_RESPONSE : MS_CHAP_RESPONSE);
        if (challenge == null || response == null || response.length != RESPONSE_LENGTH) {
            return null;
        }
        byte[] ntResponse = Arrays.copyOfRange(response, 26, 50);
        if (v2) {
            if (challenge.length != 16) {
                return null;
            }
            int at = request.findAttribute(USER_NAME);
            byte[] name = new byte[(request.buffer().getByte(at + 1) & 0xFF) - 2];
            request.buffer().getBytes(at + 2, name);
            byte[] hash = MsChap.challengeHash(Arrays.copyOfRange(response, 2, 18), challenge, MsChap.v2UserName(name));
            return new MsChapRequest(hash, ntResponse, response[0] & 0xFF, hash, true);
        }
        if (challenge.length != 8 || (response[1] & 1) == 0) {
            return null; // without the NT-Response only the LAN Manager response remains: not supported
        }
        return new MsChapRequest(challenge, ntResponse, response[0] & 0xFF, null, false);
    }

    private void succeeded(AccessContext context, MsChapRequest r, byte[] ntHashHash) {
        MsChapOutcome outcome = cache(context).msChap;
        outcome.success = true;
        outcome.ident = r.ident();
        outcome.ntHashHash = ntHashHash;
        outcome.ntResponse = r.ntResponse();
        outcome.challengeHash = r.challengeHash();
    }

    // ---- credential verifiers (ADR 0025) -------------------------------------------------------

    private static String methodName(int method) {
        return switch (method) {
            case AccessRequests.METHOD_PAP -> "PAP";
            case AccessRequests.METHOD_CHAP -> "CHAP";
            case AccessRequests.METHOD_MS_CHAP -> "MS-CHAP";
            case AccessRequests.METHOD_MS_CHAP2 -> "MS-CHAPv2";
            default -> "method " + method;
        };
    }

    /**
     * The verifier that checks this user's credential: the one {@code Auth-Type} names, else the store's ({@code
     * auth.store.<name>.verifier}) for a user without a password of its own; {@code null} for a local check.
     */
    private String verifierFor(String authType, String store, List<AttributeItem> passwords) {
        if (!authType.isEmpty() && stores.verifiers().containsKey(authType)) {
            return authType;
        }
        String forStore = stores.storeVerifiers().get(store);
        return forStore != null && passwords.isEmpty() ? forStore : null;
    }

    /** Asks a verifier: {@link #ACCEPT}, {@link #REJECT}, or {@link #DROP} when it cannot tell. */
    private int verify(AccessContext context, int method, String name, String userName) {
        CredentialVerifier verifier = stores.verifiers().get(name);
        try {
            CredentialVerifier.Result result;
            MsChapRequest r = null;
            if (isMsChap(method)) {
                r = msChapRequest(context.request(), method);
                if (r == null) {
                    return REJECT;
                }
                result = verifier.verifyMsChap(userName, r.challenge(), r.ntResponse(), r.v2());
            } else if (method == AccessRequests.METHOD_PAP) {
                byte[] password = papPassword(context);
                if (password == null) {
                    return REJECT;
                }
                try {
                    result = verifier.verifyPassword(userName, password);
                } finally {
                    Arrays.fill(password, (byte) 0);
                }
            } else {
                result = CredentialVerifier.Result.UNSUPPORTED; // CHAP needs a cleartext password
            }
            if (result.outcome() == CredentialVerifier.Outcome.UNSUPPORTED) {
                warnOnce(
                        "verifier-unsupported:" + name + ":" + method,
                        "verifier {} cannot check this method ({}): rejected",
                        name,
                        methodName(method));
                return REJECT;
            }
            if (!result.accepted()) {
                return REJECT;
            }
            if (r != null) {
                if (result.ntHashHash() == null || result.ntHashHash().length != 16) {
                    warnOnce(
                            "verifier-key:" + name,
                            "verifier {} accepted MS-CHAP without a session key: rejected",
                            name);
                    return REJECT;
                }
                succeeded(context, r, result.ntHashHash());
            }
            return ACCEPT;
        } catch (StoreUnavailableException e) {
            warnOnce(
                    "verifier-unavailable:" + name + ":" + e.getMessage(),
                    "verifier {} unavailable, requests are not answered: {}",
                    name,
                    e.getMessage());
            return DROP;
        }
    }

    /** MS-CHAP2-Success and the MPPE keys (v2), or MS-CHAP-MPPE-Keys (v1). */
    private void writeMsChapSuccess(AccessContext context, int method) {
        MsChapOutcome outcome = cache(context).msChap;
        if (!outcome.success) {
            return; // not MS-CHAP, or Auth-Type := Accept without a check: nothing to prove to the client
        }
        RadiusPacketEncoder out = context.reply();
        byte[] secret = context.nas().secret();
        byte[] authenticator = new byte[16];
        context.request().buffer().getBytes(context.request().authenticatorOffset(), authenticator);
        if (method == AccessRequests.METHOD_MS_CHAP2) {
            String success =
                    MsChap.authenticatorResponseFromKey(outcome.ntHashHash, outcome.ntResponse, outcome.challengeHash);
            byte[] value = new byte[1 + success.length()];
            value[0] = (byte) outcome.ident;
            System.arraycopy(success.getBytes(StandardCharsets.US_ASCII), 0, value, 1, success.length());
            out.vendorAttribute(MICROSOFT, MS_CHAP2_SUCCESS, value);
            byte[] master = MsChap.masterKeyFromKey(outcome.ntHashHash, outcome.ntResponse);
            int salt = saltRandom.nextInt(0x8000) & ~1; // two different salts, high bit set (RFC 2548)
            out.vendorAttribute(
                    MICROSOFT,
                    MS_MPPE_SEND_KEY,
                    MsChap.encryptKey(MsChap.serverKey(master, true), secret, authenticator, salt(salt)));
            out.vendorAttribute(
                    MICROSOFT,
                    MS_MPPE_RECV_KEY,
                    MsChap.encryptKey(MsChap.serverKey(master, false), secret, authenticator, salt(salt | 1)));
        } else {
            out.vendorAttribute(
                    MICROSOFT,
                    MS_CHAP_MPPE_KEYS,
                    MsChap.encryptV1Keys(new byte[8], outcome.ntHashHash, secret, authenticator));
        }
    }

    private static byte[] salt(int value) {
        return new byte[] {(byte) (0x80 | (value >>> 8)), (byte) value};
    }

    /** MS-CHAP-Error "authentication failure" (E=691), no retry; the reason stays in the logs. */
    private static void writeMsChapError(AccessContext context, int method) {
        RadiusPacket request = context.request();
        byte[] response =
                vendorValue(request, method == AccessRequests.METHOD_MS_CHAP2 ? MS_CHAP2_RESPONSE : MS_CHAP_RESPONSE);
        int ident = response == null || response.length == 0 ? 0 : response[0] & 0xFF;
        String text = "E=691 R=0";
        if (method == AccessRequests.METHOD_MS_CHAP2) {
            byte[] challenge = vendorValue(request, MS_CHAP_CHALLENGE);
            text += " C="
                    + (challenge == null
                            ? ""
                            : HexFormat.of().formatHex(challenge).toUpperCase(Locale.ROOT)) + " V=3";
        }
        byte[] value = new byte[1 + text.length()];
        value[0] = (byte) ident;
        System.arraycopy(text.getBytes(StandardCharsets.US_ASCII), 0, value, 1, text.length());
        context.reply().vendorAttribute(MICROSOFT, MS_CHAP_ERROR, value);
    }

    /** The value of a Microsoft vendor attribute (RFC 2548 layout), or {@code null}. */
    private static byte[] vendorValue(RadiusPacket request, int vendorType) {
        org.agrona.DirectBuffer b = request.buffer();
        for (int pos = request.attributesOffset(); pos + 2 <= request.attributesEnd(); ) {
            int type = b.getByte(pos) & 0xFF;
            int length = b.getByte(pos + 1) & 0xFF;
            if (length < 2) {
                return null;
            }
            if (type == 26 && length >= 8 && b.getInt(pos + 2, java.nio.ByteOrder.BIG_ENDIAN) == MICROSOFT) {
                int vType = b.getByte(pos + 6) & 0xFF;
                int vLength = b.getByte(pos + 7) & 0xFF;
                if (vType == vendorType && vLength >= 2 && 6 + vLength <= length) {
                    byte[] value = new byte[vLength - 2];
                    b.getBytes(pos + 8, value);
                    return value;
                }
            }
            pos += length;
        }
        return null;
    }

    // ---- simultaneous use ----------------------------------------------------------------------

    private static final String SIMULTANEOUS_USE = "Simultaneous-Use";

    private static String simultaneousUse(List<AttributeItem> check) {
        for (AttributeItem item : check) {
            if (item.attribute().equalsIgnoreCase(SIMULTANEOUS_USE)) {
                return item.value();
            }
        }
        return null;
    }

    /**
     * Applies {@code Simultaneous-Use} after a successful authentication (ADR 0023): the cluster counts the user's
     * devices online and reserved. Over the limit → Reject; no answer from the cluster → no answer to the NAS; before
     * the cluster counts users (state version 6) the limit is ignored, as before.
     */
    private int limit(AccessContext context, RadiusPacket request, String store, String value) {
        int maxDevices;
        try {
            maxDevices = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            maxDevices = -1;
        }
        if (maxDevices < 0 || maxDevices > 0xFFFF) {
            warnOnce(
                    "simultaneous-use:" + store,
                    "store {}: Simultaneous-Use is not a number from 0 to 65535;" + " such users are rejected",
                    store);
            return REJECT;
        }
        int at = request.findAttribute(USER_NAME);
        long user = UserKeys.user(request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
        int station = request.findAttribute(CALLING_STATION_ID);
        long device = station < 0
                ? 0
                : UserKeys.device(
                        request.buffer(), station + 2, (request.buffer().getByte(station + 1) & 0xFF) - 2);
        return switch (context.sessionLimits().reserve(user, device, maxDevices)) {
            case SessionLimits.GRANTED -> ACCEPT;
            case SessionLimits.DENIED -> REJECT;
            case SessionLimits.UNSUPPORTED -> {
                warnOnce(
                        "simultaneous-use-unsupported",
                        "Simultaneous-Use is not applied until the cluster activates state version 6",
                        null);
                yield ACCEPT;
            }
            default -> DROP;
        };
    }

    // ---- credentials -------------------------------------------------------------------------

    private boolean authenticate(
            AccessContext context, int method, Found found, String userName, List<AttributeItem> passwords) {
        Object2LongHashMap<String> verified = cache(context).verified;
        if (isMsChap(method)) {
            return msChap(context, method, found, passwords);
        }
        if (method == AccessRequests.METHOD_CHAP) {
            if (!stores.chap().getOrDefault(found.store(), false)) {
                warnOnce(
                        "chap:" + found.store(),
                        "CHAP request for store {}, which does not allow CHAP"
                                + " (auth.store.<name>.chap = true needs cleartext passwords): rejected",
                        found.store());
                return false;
            }
            for (AttributeItem p : passwords) {
                if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT)) {
                    byte[] clear = p.value().getBytes(StandardCharsets.UTF_8);
                    return context.credentials().verifyChap(context.request(), new UnsafeBuffer(clear), 0, clear.length)
                            == AccessRequests.CHAP_MATCH;
                }
            }
            return false;
        }
        byte[] password = papPassword(context);
        if (password == null) {
            return false;
        }
        try {
            return checkPassword(context, found, userName, passwords, password);
        } finally {
            Arrays.fill(password, (byte) 0);
        }
    }

    /**
     * A PAP password against the user's stored credentials: the first usable one decides; successful slow-hash checks
     * are cached.
     */
    private boolean checkPassword(
            AccessContext context, Found found, String userName, List<AttributeItem> passwords, byte[] password) {
        Object2LongHashMap<String> verified = cache(context).verified;
        for (AttributeItem p : passwords) {
            if (!PasswordCheck.isPassword(p.attribute())) {
                continue; // NT-Password / LM-Password: MS-CHAP (5.6)
            }
            if (BCrypt.cost(p.value()) > stores.bcryptMaxCost()) {
                warnOnce(
                        "bcrypt-cost:" + found.store(),
                        "store {}: a bcrypt hash costs more than auth.bcrypt.max.cost; such users are rejected",
                        found.store());
                return false;
            }
            boolean slow = PasswordCheck.isSlow(p.attribute(), p.value());
            String key = slow ? verifiedKey(userName, p.value(), password) : null;
            long now = clockMillis.getAsLong();
            long until = key == null ? Long.MIN_VALUE : verified.getValue(key);
            if (until != Long.MIN_VALUE && until - now > 0) {
                return true;
            }
            if (PasswordCheck.verify(p.attribute(), p.value(), password)) {
                if (key != null && ttlMillis > 0) {
                    if (verified.size() >= stores.cacheMax()) {
                        verified.clear();
                    }
                    verified.put(key, now + ttlMillis);
                }
                return true;
            }
            return false; // the first usable password decides
        }
        warnOnce(
                "no-password:" + found.store(),
                "users of store {} without a usable password are rejected"
                        + " (supported: Cleartext-, Crypt- ($5$/$6$/$2b$), SSHA*, PBKDF2-Password)",
                found.store());
        return false;
    }

    /** A key that proves knowledge of the password without keeping it: SHA-256(random salt, stored, password). */
    private String verifiedKey(String userName, String stored, byte[] password) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(verifierSalt);
            sha.update(stored.getBytes(StandardCharsets.UTF_8));
            sha.update((byte) 0);
            sha.update(password);
            return userName + '\0' + HexFormat.of().formatHex(sha.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- reply -------------------------------------------------------------------------------

    /** Adds group reply items: {@code +=} always, {@code =} and {@code :=} only if the user did not set it. */
    private static void merge(List<AttributeItem> reply, List<AttributeItem> group) {
        for (AttributeItem item : group) {
            boolean set = reply.stream().anyMatch(r -> r.attribute().equalsIgnoreCase(item.attribute()));
            if (item.op().equals("+=") || !set) {
                reply.add(item);
            }
        }
    }

    /**
     * Writes the reply items a NAS entry may receive: standard attributes always, vendor attributes only of its vendors
     * ({@link AuthStores#replyVendors()}). Each distinct item is encoded once and kept.
     */
    private void encode(
            Object2ObjectHashMap<AttributeItem, Encoded> encoded,
            List<AttributeItem> reply,
            RadiusPacketEncoder out,
            String nas) {
        IntHashSet vendors = stores.replyVendors().get(nas);
        for (AttributeItem item : reply) {
            Encoded e = encoded.get(item);
            if (e == null && perRequest(item)) {
                e = encode(item); // values that change per request (ADR 0049, 0050) would only churn the cache
            } else if (e == null) {
                e = encode(item);
                if (encoded.size() >= stores.cacheMax()) {
                    encoded.clear();
                }
                encoded.put(item, e);
            }
            if (e.value() == null) {
                continue; // not encodable: warned when first seen
            }
            if (e.vendorId() == 0) {
                out.attribute(e.number(), e.value());
            } else if (vendors == null || vendors.contains(e.vendorId())) {
                out.vendorAttribute(e.vendorId(), e.number(), e.value());
            } else {
                AtomicLong count = filtered.get(nas); // absent only for a moment around a reload
                if (count != null) {
                    count.incrementAndGet();
                }
            }
        }
    }

    private static boolean perRequest(AttributeItem item) {
        return item.attribute().equalsIgnoreCase("Framed-IP-Address")
                || item.attribute().equalsIgnoreCase("Session-Timeout");
    }

    /** One reply item, encoded; {@code value == null} if it cannot be sent. */
    private record Encoded(int vendorId, int number, byte[] value) {}

    private Encoded encode(AttributeItem item) {
        String problem = AuthStores.replyProblem(dictionary, item);
        if (problem != null) {
            warnOnce("reply:" + item.attribute(), "{}: not sent", problem);
            return new Encoded(0, 0, null);
        }
        AttributeDef def = dictionary.find(item.attribute());
        byte[] value = AttributeText.encode(def, item.value());
        if (value.length > RadiusPacketEncoder.MAX_VALUE_LENGTH - (def.vendorId() == 0 ? 0 : 6)) {
            warnOnce("reply-long:" + item.attribute(), "reply item {} is too long: not sent", item.attribute());
            return new Encoded(0, 0, null);
        }
        return new Encoded(def.vendorId(), def.number(), value);
    }

    /** Vendor attributes left out of replies because the NAS entry is of another vendor, per NAS entry. */
    private static Map<String, AtomicLong> counters(AuthStores stores, Map<String, AtomicLong> previous) {
        Map<String, AtomicLong> next = new java.util.HashMap<>();
        stores.replyVendors().keySet().forEach(nas -> next.put(nas, previous.getOrDefault(nas, new AtomicLong())));
        return Map.copyOf(next);
    }

    /**
     * Takes the stores of a reloaded configuration (ADR 0054): requests from now on use them, workers drop their
     * caches, and the previous stores are closed after {@code grace} (requests still using them finish).
     */
    void reload(AuthStores next, java.time.Duration grace) {
        AuthStores previous = stores;
        filtered = counters(next, filtered);
        ttlMillis = next.cacheTtl().toMillis();
        stores = next;
        generation++;
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

    long filtered(String nas) {
        AtomicLong count = filtered.get(nas);
        return count == null ? 0 : count.get();
    }

    @Override
    public void writeMetrics(PrometheusWriter w, String gateway) {
        w.counter(
                "radiusward_gateway_access_reply_items_filtered_total",
                "Vendor attributes left out of Access-Accepts because the NAS entry is of another vendor");
        new TreeMap<>(filtered).forEach((nas, count) -> w.sample(count.get(), "gateway", gateway, "nas", nas));
        EapTlsConfig tls = stores.eap().tls();
        if (tls != null) {
            w.counter(
                    "radiusward_gateway_eap_tls_reloads_total",
                    "Changes of the EAP TLS certificate, key, CA or CRL files: loaded, or failed (previous kept)");
            w.sample(tls.context().reloads(), "gateway", gateway, "result", "loaded");
            w.sample(tls.context().reloadFailures(), "gateway", gateway, "result", "failed");
            w.counter(
                    "radiusward_gateway_eap_tls_resumptions_total",
                    "EAP TLS handshakes that resumed an earlier session (PEAP and TTLS skip their inner method)");
            w.sample(tls.context().resumptions(), "gateway", gateway);
        }
        if (!stores.verifiers().isEmpty()) {
            w.counter(
                    "radiusward_gateway_verifier_events_total",
                    "What credential verifiers did: accepted, rejected, unavailable and their own events");
            new TreeMap<>(stores.verifiers())
                    .forEach((name, verifier) -> new TreeMap<>(verifier.counters())
                            .forEach((event, count) ->
                                    w.sample(count, "gateway", gateway, "verifier", name, "event", event)));
        }
    }

    private static String string(RadiusPacket request, int type) {
        int at = request.findAttribute(type);
        if (at < 0) {
            return null;
        }
        return request.buffer()
                .getStringWithoutLengthUtf8(at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
    }

    private boolean firstWarning(String key) {
        synchronized (warned) { // rare: only for problems that are logged once
            return warned.add(key);
        }
    }

    private void warnOnce(String key, String message, Object detail) {
        if (firstWarning(key)) {
            LOG.warn(message, detail);
        }
    }

    private void warnOnce(String key, String message, Object a, Object b) {
        if (firstWarning(key)) {
            LOG.warn(message, a, b);
        }
    }

    @Override
    public void close() {
        stores.close();
    }
}
