/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.radius.codec.AccessRequests;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.LongSupplier;
import org.agrona.collections.Object2LongHashMap;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * A user's credential checked against what the stores hold (ADR 0021, ADR 0025): a credential verifier when
 * {@code Auth-Type} or the store names one, else the stored passwords for PAP and the cleartext one for CHAP. Slow
 * hashes that matched are remembered for the cache's lifetime, under a key that does not keep the password.
 */
final class PasswordChecks {

    private final StoreAccessHandler handler;
    private final MsChapAuthenticator msChap;
    private final LongSupplier clockMillis;
    private final OnceLogger once;
    private final byte[] verifierSalt = new byte[16];

    PasswordChecks(StoreAccessHandler handler, MsChapAuthenticator msChap, LongSupplier clockMillis, OnceLogger once) {
        this.handler = handler;
        this.msChap = msChap;
        this.clockMillis = clockMillis;
        this.once = once;
        new SecureRandom().nextBytes(verifierSalt);
    }

    /**
     * The verifier that checks this user's credential: the one {@code Auth-Type} names, else the store's ({@code
     * auth.store.<name>.verifier}) for a user without a password of its own; {@code null} for a local check.
     */
    String verifierFor(String authType, String store, List<AttributeItem> passwords) {
        if (!authType.isEmpty() && handler.stores().verifiers().containsKey(authType)) {
            return authType;
        }
        String forStore = handler.stores().storeVerifiers().get(store);
        return forStore != null && passwords.isEmpty() ? forStore : null;
    }

    /** Asks a verifier: {@link #ACCEPT}, {@link #REJECT}, or {@link #DROP} when it cannot tell. */
    int verify(AuthRequest auth, int method, String name, String userName) {
        AccessContext context = auth.context();
        CredentialVerifier verifier = handler.stores().verifiers().get(name);
        try {
            CredentialVerifier.Result result;
            MsChapAuthenticator.Request r = null;
            if (MsChapAuthenticator.isMsChap(method)) {
                r = MsChapAuthenticator.request(context.request(), method);
                if (r == null) {
                    return AccessHandler.REJECT;
                }
                result = verifier.verifyMsChap(userName, r.challenge(), r.ntResponse(), r.v2());
            } else if (method == AccessRequests.METHOD_PAP) {
                byte[] password = handler.papPassword(auth);
                if (password == null) {
                    return AccessHandler.REJECT;
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
                once.warn(
                        "verifier-unsupported:" + name + ":" + method,
                        "verifier {} cannot check this method ({}): rejected",
                        name,
                        StoreAccessHandler.methodName(method));
                return AccessHandler.REJECT;
            }
            if (!result.accepted()) {
                return AccessHandler.REJECT;
            }
            if (r != null) {
                if (result.ntHashHash() == null || result.ntHashHash().length != 16) {
                    once.warn(
                            "verifier-key:" + name,
                            "verifier {} accepted MS-CHAP without a session key: rejected",
                            name);
                    return AccessHandler.REJECT;
                }
                MsChapAuthenticator.succeeded(auth, r, result.ntHashHash());
            }
            return AccessHandler.ACCEPT;
        } catch (StoreUnavailableException e) {
            once.warn(
                    "verifier-unavailable:" + name + ":" + e.getMessage(),
                    "verifier {} unavailable, requests are not answered: {}",
                    name,
                    e.getMessage());
            return AccessHandler.DROP;
        }
    }

    boolean authenticate(
            AuthRequest auth, int method, UserDirectory.Found found, String userName, List<AttributeItem> passwords) {
        AccessContext context = auth.context();
        Object2LongHashMap<String> verified = auth.caches().verified;
        if (MsChapAuthenticator.isMsChap(method)) {
            return msChap.verify(auth, method, found, passwords);
        }
        if (method == AccessRequests.METHOD_CHAP) {
            if (!handler.stores().chap().getOrDefault(found.store(), false)) {
                once.warn(
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
        byte[] password = handler.papPassword(auth);
        if (password == null) {
            return false;
        }
        try {
            return checkPassword(auth, found, userName, passwords, password);
        } finally {
            Arrays.fill(password, (byte) 0);
        }
    }

    /**
     * A PAP password against the user's stored credentials: the first usable one decides; successful slow-hash checks
     * are cached.
     */
    boolean checkPassword(
            AuthRequest auth,
            UserDirectory.Found found,
            String userName,
            List<AttributeItem> passwords,
            byte[] password) {
        AccessContext context = auth.context();
        Object2LongHashMap<String> verified = auth.caches().verified;
        for (AttributeItem p : passwords) {
            if (!PasswordCheck.isPassword(p.attribute())) {
                continue; // not a password item (NT- and LM-Password are: their hash of the typed password)
            }
            if (BCrypt.cost(p.value()) > handler.stores().bcryptMaxCost()) {
                once.warn(
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
                long ttlMillis = handler.stores().cacheTtl().toMillis();
                if (key != null && ttlMillis > 0) {
                    if (verified.size() >= handler.stores().cacheMax()) {
                        verified.clear();
                    }
                    verified.put(key, now + ttlMillis);
                }
                return true;
            }
            return false; // the first usable password decides
        }
        once.warn(
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
}
