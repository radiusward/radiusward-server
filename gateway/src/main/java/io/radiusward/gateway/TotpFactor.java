/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The TOTP second factor of users with a {@code TOTP-Secret} (ADR 0053): the code appended to the PAP password, or
 * asked for in an Access-Challenge after the password was right. A code is accepted once per user.
 */
final class TotpFactor {

    static final String SECRET = "TOTP-Secret";
    /** {@link #check}: the code of a challenge was right; the password was checked in the round that asked. */
    static final int CODE_OK = -1;
    /** {@link #check}: check the password, then ask for the code ({@link #challenge}). */
    static final int ASK = -2;

    private static final int STATE = 24;
    private static final int REPLY_MESSAGE = 18;
    private static final int MAX_CHALLENGES = 10_000;

    private record Pending(String user, long expiresMillis) {}

    private final LongSupplier clockMillis;
    private final SecureRandom random;
    private final OnceLogger once;
    private final ConcurrentHashMap<String, Pending> challenges = new ConcurrentHashMap<>();
    /** The last time step used per user: a code is accepted once. */
    private final ConcurrentHashMap<String, Long> usedSteps = new ConcurrentHashMap<>();

    private final Supplier<AccessPolicies> policies;

    TotpFactor(LongSupplier clockMillis, SecureRandom random, OnceLogger once, Supplier<AccessPolicies> policies) {
        this.policies = policies;
        this.clockMillis = clockMillis;
        this.random = random;
        this.once = once;
    }

    /** The user's TOTP secret among the authorization's restrictions, {@code null} without one. */
    static String secretOf(List<AttributeItem> restrictions) {
        for (AttributeItem item : restrictions) {
            if (item.attribute().equalsIgnoreCase(SECRET)) {
                return item.value();
            }
        }
        return null;
    }

    /**
     * The second factor: {@link AccessHandler#ACCEPT} (append mode: the code was right, the password before it
     * remains to be checked: {@link AuthRequest#papPassword()}), {@link #CODE_OK}, {@link #ASK}, or {@link
     * AccessHandler#REJECT}.
     */
    int check(AuthRequest auth, int method, String userName, String secret) {
        AccessContext context = auth.context();
        Totp t = policies.get().totp();
        if (method != AccessRequests.METHOD_PAP) {
            once.warn(
                    "totp:" + method,
                    "users with a TOTP-Secret need PAP; {} is rejected",
                    StoreAccessHandler.methodName(method));
            StoreAccessHandler.because(context, "TOTP needs PAP", "");
            return AccessHandler.REJECT;
        }
        byte[] key = Totp.base32(secret);
        if (key == null) {
            once.warn("totp-secret:" + userName, "TOTP-Secret of user {} is not base32 of 10 bytes or more", userName);
            StoreAccessHandler.because(context, "TOTP-Secret not understood", "");
            return AccessHandler.REJECT;
        }
        byte[] typed = auth.papPassword();
        if (typed == null) {
            return AccessHandler.REJECT;
        }
        try {
            if (t.append()) {
                if (typed.length < t.digits()) {
                    StoreAccessHandler.because(context, "no TOTP code after the password", "");
                    return AccessHandler.REJECT;
                }
                int split = typed.length - t.digits();
                if (!codeAccepted(
                        context, t, key, userName, new String(typed, split, t.digits(), StandardCharsets.US_ASCII))) {
                    return AccessHandler.REJECT;
                }
                auth.papRemainder(Arrays.copyOf(typed, split));
                return AccessHandler.ACCEPT;
            }
            RadiusPacket request = context.request();
            int at = request.findAttribute(STATE);
            Pending pending = null;
            if (at >= 0) {
                pending = challenges.remove(
                        stateKey(request.buffer(), at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2));
            }
            if (pending == null) {
                return ASK;
            }
            if (!pending.user().equals(userName) || pending.expiresMillis() < clockMillis.getAsLong()) {
                StoreAccessHandler.because(context, "TOTP challenge expired or of another user", "");
                return AccessHandler.REJECT;
            }
            return codeAccepted(context, t, key, userName, new String(typed, StandardCharsets.US_ASCII))
                    ? CODE_OK
                    : AccessHandler.REJECT;
        } finally {
            Arrays.fill(typed, (byte) 0);
            Arrays.fill(key, (byte) 0);
        }
    }

    private boolean codeAccepted(AccessContext context, Totp t, byte[] key, String userName, String code) {
        long step = t.match(key, code, clockMillis.getAsLong() / 1000);
        if (step < 0) {
            StoreAccessHandler.because(context, "wrong TOTP code", "");
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
            StoreAccessHandler.because(context, "TOTP code already used", "");
        }
        return fresh[0];
    }

    /** Asks for the code: an Access-Challenge with a fresh State and the prompt. */
    int challenge(AccessContext context, String userName) {
        Totp totp = policies.get().totp();
        long now = clockMillis.getAsLong();
        if (challenges.size() >= MAX_CHALLENGES) {
            challenges.values().removeIf(p -> p.expiresMillis() < now);
            if (challenges.size() >= MAX_CHALLENGES) {
                once.warn("totp-full", "{} TOTP challenges open: further ones are not answered", MAX_CHALLENGES);
                return AccessHandler.DROP;
            }
        }
        byte[] state = new byte[16];
        random.nextBytes(state);
        challenges.put(
                stateKey(new UnsafeBuffer(state), 0, state.length),
                new Pending(userName, now + totp.timeout().toMillis()));
        context.reply().attribute(STATE, state);
        context.reply().attribute(REPLY_MESSAGE, totp.prompt());
        StoreAccessHandler.note(context, "password right, TOTP code asked for", "");
        return AccessHandler.CHALLENGE;
    }

    private static String stateKey(DirectBuffer buffer, int offset, int length) {
        return io.radiusward.radius.codec.AttributeValues.hex(buffer, offset, length);
    }
}
