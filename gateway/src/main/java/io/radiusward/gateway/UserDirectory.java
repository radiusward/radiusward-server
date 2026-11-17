/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.auth.UserRecord;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.dictionary.AttributeDef;
import io.radiusward.radius.dictionary.Dictionary;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.agrona.collections.IntHashSet;
import org.agrona.collections.Object2ObjectHashMap;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Finds users in the identity stores and authorizes them: the first store of the NAS entry that knows the user, its
 * check items, the groups whose conditions hold (their check items, Auth-Type, Simultaneous-Use and reply items) and
 * the restrictions to apply. Look-ups are cached per worker for {@code auth.cache.ttl}. A store that cannot answer
 * makes the result {@link AccessHandler#DROP}: it might know the user.
 */
final class UserDirectory {

    /** A cached look-up: the user, or none, until {@code expires}. */
    record Cached(Optional<UserRecord> user, long expires) {}

    /** A user and the store it was found in ({@code ""}: none, a certificate or tunnel identity). */
    record Found(String store, UserRecord user) {}

    private final Supplier<AuthStores> stores; // replaced by a reload (ADR 0054)
    private final Dictionary dictionary;
    private final LongSupplier clockMillis;
    private final AuthMetrics metrics;
    private final CheckItems checkItems;
    private final Restrictions restrictions;
    private final OnceLogger once;

    UserDirectory(
            Supplier<AuthStores> stores,
            Dictionary dictionary,
            LongSupplier clockMillis,
            AuthMetrics metrics,
            CheckItems checkItems,
            Restrictions restrictions,
            OnceLogger once) {
        this.stores = stores;
        this.dictionary = dictionary;
        this.clockMillis = clockMillis;
        this.metrics = metrics;
        this.checkItems = checkItems;
        this.restrictions = restrictions;
        this.once = once;
    }

    /**
     * The authorization of a user: its store entry, check items and the groups that apply. {@code code} is
     * {@link AccessHandler#ACCEPT} to go on, {@link AccessHandler#REJECT} (unknown user, failed check, Auth-Type Reject) or {@link AccessHandler#DROP}.
     */
    record Authorization(
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
     * @param code {@link AccessHandler#ACCEPT} (still let in), {@link AccessHandler#REJECT} (rejected now: disabled, or {@code Auth-Type :=
     *     Reject}), {@link AccessHandler#DROP} (no store answered); {@code found}: whether a store has the user
     * @param reply the reply items the user would get now, for the NAS entry's vendors
     */
    record Review(int code, boolean found, List<AttributeItem> reply) {}

    private final AccessContext sweepContext = new AccessContext();
    private final StoreAccessHandler.WorkerCache sweepCaches = new StoreAccessHandler.WorkerCache();
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
            found = find(sweepCaches, nas.name(), userName);
        } catch (StoreUnavailableException e) {
            return new Review(AccessHandler.DROP, false, List.of());
        }
        if (found == null) {
            return new Review(AccessHandler.REJECT, false, List.of());
        }
        Authorization a = authorize(sweepCaches.request.begin(sweepContext), userName, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new Review(a.code(), true, List.of());
        }
        IntHashSet vendors = stores.get().replyVendors().get(nas.name());
        List<AttributeItem> reply = new ArrayList<>();
        for (AttributeItem item : a.reply()) {
            AttributeDef def = dictionary.find(item.attribute());
            if (def != null && (def.vendorId() == 0 || vendors == null || vendors.contains(def.vendorId()))) {
                reply.add(item);
            }
        }
        return new Review(AccessHandler.ACCEPT, true, reply);
    }

    /** Looks {@code userName} up and evaluates its checks and groups; {@code optional}: a missing user is empty. */
    Authorization authorize(AuthRequest auth, String userName, boolean optional) {
        AccessContext context = auth.context();
        RadiusPacket request = context.request();
        Found found;
        try {
            found = find(auth.caches(), context.nas().name(), userName);
        } catch (StoreUnavailableException e) {
            once.warn("unavailable:" + e.getMessage(), "identity store unavailable, requests are not answered: {}", e);
            StoreAccessHandler.because(context, "identity store unavailable: ", e.getMessage());
            return Authorization.of(AccessHandler.DROP);
        }
        if (found == null) {
            if (!optional) {
                StoreAccessHandler.because(context, "user not in any store: ", userName);
                return Authorization.of(AccessHandler.REJECT);
            }
            // EAP-TLS: the certificate is the credential; tunnels: the inner user is looked up (ADR 0028, 0029)
            found = new Found("", new UserRecord(userName, List.of(), List.of(), List.of()));
        }
        List<AttributeItem> passwords = new ArrayList<>();
        List<AttributeItem> reply = new ArrayList<>(found.user().reply());
        StoreAccessHandler.note(
                context,
                "user found in store ",
                found.store().isEmpty() ? "(none, certificate or tunnel)" : found.store());
        String authType = checkItems.checks(found.user().check(), request, passwords);
        if (authType == null) {
            StoreAccessHandler.because(
                    context, "a check item of the user does not hold (Expiration or a comparison)", "");
            return Authorization.of(AccessHandler.REJECT);
        }
        String limit = Restrictions.simultaneousUse(found.user().check());
        for (UserRecord.Group group : found.user().groups()) {
            List<AttributeItem> groupPasswords = new ArrayList<>();
            String groupAuthType = checkItems.checks(group.check(), request, groupPasswords);
            if (groupAuthType == null) {
                StoreAccessHandler.note(context, "group does not apply: ", group.name());
                continue; // the group's conditions do not hold: it does not apply
            }
            StoreAccessHandler.note(context, "group applies: ", group.name());
            if (groupAuthType.equalsIgnoreCase("Reject")) {
                StoreAccessHandler.because(context, "Auth-Type := Reject in group ", group.name());
                return Authorization.of(AccessHandler.REJECT);
            }
            if (authType.isEmpty()) {
                authType = groupAuthType;
            }
            if (limit == null) {
                limit = Restrictions.simultaneousUse(
                        group.check()); // the user's own limit wins, then the first group's
            }
            passwords.addAll(groupPasswords);
            ReplyEncoder.merge(reply, group.reply());
        }
        if (authType.equalsIgnoreCase("Reject")) {
            StoreAccessHandler.because(context, "Auth-Type := Reject", "");
            return Authorization.of(AccessHandler.REJECT);
        }
        if (!authType.isEmpty()) {
            StoreAccessHandler.note(context, "Auth-Type: ", authType);
        }
        List<AttributeItem> collected = new ArrayList<>();
        restrictions.collect(found.user().check(), collected);
        for (UserRecord.Group group : found.user().groups()) {
            if (checkItems.checks(group.check(), request, new ArrayList<>()) != null) {
                restrictions.collect(group.check(), collected);
            }
        }
        return new Authorization(AccessHandler.ACCEPT, found, authType, passwords, reply, limit, collected);
    }

    /** The first store of the NAS entry that knows {@code userName}; {@code null}: none does. */
    Found find(StoreAccessHandler.WorkerCache cache, String nas, String userName) throws StoreUnavailableException {
        Object2ObjectHashMap<String, Cached> users = cache.users;
        StoreUnavailableException unavailable = null;
        long now = clockMillis.getAsLong();
        AuthStores stores = this.stores.get();
        long ttlMillis = stores.cacheTtl().toMillis();
        for (String name : stores.storesFor(nas)) {
            String key = name + '\0' + userName;
            Cached cached = users.get(key);
            Optional<UserRecord> user;
            if (cached != null && cached.expires() - now > 0) {
                user = cached.user();
            } else {
                IdentityStore store = stores.stores().get(name);
                StoreLookups measured = metrics.lookups(name);
                long started = System.nanoTime();
                try {
                    user = store.lookup(userName);
                } catch (StoreUnavailableException e) {
                    measured.record(System.nanoTime() - started, StoreLookups.UNAVAILABLE);
                    unavailable = e;
                    continue;
                }
                measured.record(
                        System.nanoTime() - started, user.isPresent() ? StoreLookups.FOUND : StoreLookups.NOT_FOUND);
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

    /** The stores were reloaded: the sweep forgets what it looked up in the previous ones. */
    synchronized void reload() {
        sweepCaches.users.clear();
        sweepCaches.verified.clear();
        sweepCaches.encoded.clear();
    }
}
