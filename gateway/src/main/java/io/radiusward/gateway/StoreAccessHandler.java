/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
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
    private final ConcurrentHashMap<String, Cached> users = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> verified = new ConcurrentHashMap<>();
    private final Set<String> warned = ConcurrentHashMap.newKeySet();
    private final byte[] verifierSalt = new byte[16];

    private record Cached(Optional<UserRecord> user, long expires) {}

    private record Found(String store, UserRecord user) {}

    StoreAccessHandler(AuthStores stores, Dictionary dictionary, LongSupplier clockMillis) {
        this.stores = stores;
        this.dictionary = dictionary;
        this.clockMillis = clockMillis;
        this.ttlMillis = stores.cacheTtl().toMillis();
        new java.security.SecureRandom().nextBytes(verifierSalt);
    }

    @Override
    public int handle(AccessContext context) {
        RadiusPacket request = context.request();
        AccessRequests credentials = context.credentials();
        int method = credentials.method(request);
        if (method != AccessRequests.METHOD_PAP && method != AccessRequests.METHOD_CHAP) {
            return REJECT; // MS-CHAP (5.6) and EAP (5.7) come later; none or several methods are never valid
        }
        String userName = string(request, USER_NAME);
        if (userName == null || userName.isEmpty()) {
            return REJECT;
        }
        Found found;
        try {
            found = find(context.nas().name(), userName);
        } catch (StoreUnavailableException e) {
            warnOnce("unavailable:" + e.getMessage(), "identity store unavailable, requests are not answered: {}", e);
            return DROP;
        }
        if (found == null) {
            return REJECT;
        }

        List<AttributeItem> passwords = new ArrayList<>();
        List<AttributeItem> reply = new ArrayList<>(found.user().reply());
        String authType = checks(found.user().check(), request, passwords);
        if (authType == null) {
            return REJECT;
        }
        for (UserRecord.Group group : found.user().groups()) {
            List<AttributeItem> groupPasswords = new ArrayList<>();
            String groupAuthType = checks(group.check(), request, groupPasswords);
            if (groupAuthType == null) {
                continue; // the group's conditions do not hold: it does not apply
            }
            if (groupAuthType.equalsIgnoreCase("Reject")) {
                return REJECT;
            }
            if (authType.isEmpty()) {
                authType = groupAuthType;
            }
            passwords.addAll(groupPasswords);
            merge(reply, group.reply());
        }
        if (authType.equalsIgnoreCase("Reject")) {
            return REJECT;
        }
        if (!authType.equalsIgnoreCase("Accept") && !authenticate(context, method, found, userName, passwords)) {
            return REJECT;
        }
        encode(reply, context.reply());
        return ACCEPT;
    }

    // ---- look-up -------------------------------------------------------------------------------

    private Found find(String nas, String userName) throws StoreUnavailableException {
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
            } else if (name.equalsIgnoreCase("Simultaneous-Use")) {
                warnOnce("simultaneous-use", "Simultaneous-Use is not enforced yet (Phase 5.5); ignored", null);
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

    // ---- credentials -------------------------------------------------------------------------

    private boolean authenticate(
            AccessContext context, int method, Found found, String userName, List<AttributeItem> passwords) {
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
                Long until = key == null ? null : verified.get(key);
                if (until != null && until - now > 0) {
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
        } finally {
            Arrays.fill(password, (byte) 0);
            Arrays.fill(buffer.byteArray(), (byte) 0);
        }
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

    private void encode(List<AttributeItem> reply, RadiusPacketEncoder out) {
        for (AttributeItem item : reply) {
            AttributeDef def = dictionary.find(item.attribute());
            if (def == null) {
                warnOnce(
                        "reply:" + item.attribute(),
                        "reply item {} is not in the dictionary: not sent",
                        item.attribute());
                continue;
            }
            byte[] value;
            try {
                value = AttributeText.encode(def, item.value());
            } catch (IllegalArgumentException e) {
                warnOnce(
                        "reply-value:" + item.attribute(),
                        "reply item {}: {}; not sent",
                        item.attribute(),
                        e.getMessage());
                continue;
            }
            if (value.length > RadiusPacketEncoder.MAX_VALUE_LENGTH - (def.vendorId() == 0 ? 0 : 6)) {
                warnOnce("reply-long:" + item.attribute(), "reply item {} is too long: not sent", item.attribute());
                continue;
            }
            if (def.vendorId() == 0) {
                out.attribute(def.number(), value);
            } else {
                out.vendorAttribute(def.vendorId(), def.number(), value);
            }
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

    private void warnOnce(String key, String message, Object detail) {
        if (warned.add(key)) {
            LOG.warn(message, detail);
        }
    }

    private void warnOnce(String key, String message, Object a, Object b) {
        if (warned.add(key)) {
            LOG.warn(message, a, b);
        }
    }

    @Override
    public void close() {
        stores.close();
    }
}
