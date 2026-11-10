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
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
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

    private final AuthStores stores;
    private final Dictionary dictionary;
    private final LongSupplier clockMillis;
    private final long ttlMillis;
    private final ObjectHashSet<String> warned = new ObjectHashSet<>();
    /** Per NAS entry with a vendor filter; filled at construction, only read afterwards. */
    private final Object2ObjectHashMap<String, AtomicLong> filtered = new Object2ObjectHashMap<>();

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
        stores.replyVendors().keySet().forEach(nas -> filtered.put(nas, new AtomicLong()));
        this.conversations = new EapConversations(stores.eap().conversations());
    }

    @Override
    public int handle(AccessContext context) {
        int method = context.credentials().method(context.request());
        WorkerCache cache = cache(context);
        cache.msChap.reset();
        cache.eap.reset();
        int result = decide(context, method);
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
            if (inner != null) { // a tunnel: the inner user is the one authorized (ADR 0029)
                a = authorize(context, inner, c.method.innerOptional());
                if (a.code() != ACCEPT) {
                    return a.code();
                }
                found = a.found();
            }
        } else if (!authType.equalsIgnoreCase("Accept")) {
            String verifier = verifierFor(authType, found.store(), passwords);
            int checked = verifier != null
                    ? verify(context, method, verifier, userName)
                    : authenticate(context, method, found, userName, passwords) ? ACCEPT : REJECT;
            if (checked != ACCEPT) {
                return checked;
            }
        }
        if (a.limit() != null) {
            int decision = limit(context, request, found.store(), a.limit());
            if (decision != ACCEPT) {
                return decision;
            }
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
            String limit) {

        static Authorization of(int code) {
            return new Authorization(code, null, null, null, null, null);
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
            return Authorization.of(DROP);
        }
        if (found == null) {
            if (!optional) {
                return Authorization.of(REJECT);
            }
            // EAP-TLS: the certificate is the credential; tunnels: the inner user is looked up (ADR 0028, 0029)
            found = new Found("", new UserRecord(userName, List.of(), List.of(), List.of()));
        }
        List<AttributeItem> passwords = new ArrayList<>();
        List<AttributeItem> reply = new ArrayList<>(found.user().reply());
        String authType = checks(found.user().check(), request, passwords);
        if (authType == null) {
            return Authorization.of(REJECT);
        }
        String limit = simultaneousUse(found.user().check());
        for (UserRecord.Group group : found.user().groups()) {
            List<AttributeItem> groupPasswords = new ArrayList<>();
            String groupAuthType = checks(group.check(), request, groupPasswords);
            if (groupAuthType == null) {
                continue; // the group's conditions do not hold: it does not apply
            }
            if (groupAuthType.equalsIgnoreCase("Reject")) {
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
            return Authorization.of(REJECT);
        }
        return new Authorization(ACCEPT, found, authType, passwords, reply, limit);
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

    private static Instant date(String text) {
        String t = text.trim().replaceAll("\\s+", " ");
        try {
            return Instant.parse(t);
        } catch (DateTimeParseException ignored) {
            // not ISO-8601
        }
        for (DateTimeFormatter f : DATES) {
            try {
                return LocalDateTime.parse(t, f).atZone(ZoneId.systemDefault()).toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        for (DateTimeFormatter f : DAYS) {
            try {
                return LocalDate.parse(t, f)
                        .atStartOfDay(ZoneId.systemDefault())
                        .toInstant();
            } catch (DateTimeParseException ignored) {
                // next format
            }
        }
        try {
            return LocalDate.parse(t).atStartOfDay(ZoneId.systemDefault()).toInstant();
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
                    public EapMethod.Inner msChapV2(String user, byte[] challengeHash, byte[] ntResponse) {
                        return innerMsChapV2(context, user, challengeHash, ntResponse);
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
                UnsafeBuffer buffer = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
                int n = context.credentials()
                        .decryptUserPassword(context.request(), context.nas().secret(), buffer, 0);
                if (n < 0) {
                    return REJECT;
                }
                byte[] password = Arrays.copyOf(buffer.byteArray(), n);
                try {
                    result = verifier.verifyPassword(userName, password);
                } finally {
                    Arrays.fill(password, (byte) 0);
                    Arrays.fill(buffer.byteArray(), (byte) 0);
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
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[AccessRequests.MAX_PASSWORD]);
        int n = context.credentials()
                .decryptUserPassword(context.request(), context.nas().secret(), buffer, 0);
        if (n < 0) {
            return false;
        }
        byte[] password = Arrays.copyOf(buffer.byteArray(), n);
        try {
            return checkPassword(context, found, userName, passwords, password);
        } finally {
            Arrays.fill(password, (byte) 0);
            Arrays.fill(buffer.byteArray(), (byte) 0);
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
            if (e == null) {
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
                filtered.get(nas).incrementAndGet(); // present: the entry has a vendor set
            }
        }
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
