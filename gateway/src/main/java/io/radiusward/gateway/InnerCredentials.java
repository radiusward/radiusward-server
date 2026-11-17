/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.Md4;
import io.radiusward.auth.StoreUnavailableException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The credentials of a tunnel's inner user (PEAP, TTLS, TEAP: PAP, CHAP, MS-CHAP, MS-CHAPv2), checked like the same
 * methods outside a tunnel: the user looked up and authorized by the {@link StoreAccessHandler}, then a credential
 * verifier or the stored credentials, or, for a proxied realm, its home server (ADR 0044).
 */
final class InnerCredentials {

    private final StoreAccessHandler handler;
    private final OnceLogger once;

    InnerCredentials(StoreAccessHandler handler, OnceLogger once) {
        this.handler = handler;
        this.once = once;
    }

    /** A home server's verdict on the inner user: its reply kept for our Accept, the tunnel not remembered. */
    private EapMethod.Inner proxied(AccessContext context, InnerProxy.Result r) {
        EapConversations.Conversation c = StoreAccessHandler.cache(context).eap.conversation;
        if (c != null) {
            if (r.inner().code() == AccessHandler.ACCEPT) {
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
    EapMethod.Inner msChapV2(AccessContext context, String user, EapMethod.MsChapV2 exchange) {
        InnerProxy home = handler.innerProxy();
        if (home != null && home.realm(user) != null) {
            return proxied(context, home.msChapV2(user, exchange));
        }
        return msChap(context, user, exchange.challengeHash(), exchange.ntResponse(), true);
    }

    /**
     * CHAP inside a tunnel: only with the cleartext password of a store that allows CHAP, as outside it; verifiers
     * cannot answer CHAP.
     */
    EapMethod.Inner chap(AccessContext context, String user, int identifier, byte[] challenge, byte[] response) {
        InnerProxy home = handler.innerProxy();
        if (home != null && home.realm(user) != null) {
            return proxied(context, home.chap(user, identifier, challenge, response));
        }
        StoreAccessHandler.Authorization a = handler.authorize(context, user, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        if (a.authType().equalsIgnoreCase("Accept")) {
            return new EapMethod.Inner(AccessHandler.ACCEPT, null);
        }
        if (!handler.stores().chap().getOrDefault(a.found().store(), false)) {
            once.warn(
                    "chap:" + a.found().store(),
                    "CHAP request for store {}, which does not allow CHAP"
                            + " (auth.store.<name>.chap = true needs cleartext passwords): rejected",
                    a.found().store());
            return new EapMethod.Inner(AccessHandler.REJECT, null);
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
                            java.security.MessageDigest.isEqual(md5.digest(), response)
                                    ? AccessHandler.ACCEPT
                                    : AccessHandler.REJECT,
                            null);
                } catch (java.security.NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                } finally {
                    Arrays.fill(clear, (byte) 0);
                }
            }
        }
        return new EapMethod.Inner(AccessHandler.REJECT, null);
    }

    /** MS-CHAP inside a tunnel; {@code challenge} is the v2 challenge hash or the v1 challenge (both 8 bytes). */
    EapMethod.Inner msChap(AccessContext context, String user, byte[] challenge, byte[] ntResponse, boolean v2) {
        StoreAccessHandler.Authorization a = handler.authorize(context, user, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        String verifier = handler.verifierFor(a.authType(), a.found().store(), a.passwords());
        if (verifier != null) {
            try {
                CredentialVerifier.Result r =
                        handler.stores().verifiers().get(verifier).verifyMsChap(user, challenge, ntResponse, v2);
                return r.accepted() && r.ntHashHash() != null
                        ? new EapMethod.Inner(AccessHandler.ACCEPT, r.ntHashHash())
                        : new EapMethod.Inner(AccessHandler.REJECT, null);
            } catch (StoreUnavailableException e) {
                once.warn(
                        "verifier-unavailable:" + verifier + ":" + e.getMessage(),
                        "verifier {} unavailable, requests are not answered: {}",
                        verifier,
                        e.getMessage());
                return new EapMethod.Inner(AccessHandler.DROP, null);
            }
        }
        byte[] ntHash = handler.localNtHash(a.found(), a.passwords());
        if (ntHash == null
                || !java.security.MessageDigest.isEqual(MsChap.challengeResponse(challenge, ntHash), ntResponse)) {
            return new EapMethod.Inner(AccessHandler.REJECT, null);
        }
        return new EapMethod.Inner(AccessHandler.ACCEPT, Md4.digest(ntHash));
    }

    /** A password inside a tunnel (TTLS/PAP): the inner user looked up, then a verifier or the stored credentials. */
    EapMethod.Inner password(AccessContext context, String user, byte[] password) {
        InnerProxy home = handler.innerProxy();
        if (home != null && home.realm(user) != null) {
            return proxied(context, home.password(user, password));
        }
        StoreAccessHandler.Authorization a = handler.authorize(context, user, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        if (a.authType().equalsIgnoreCase("Accept")) {
            return new EapMethod.Inner(AccessHandler.ACCEPT, null);
        }
        String verifier = handler.verifierFor(a.authType(), a.found().store(), a.passwords());
        if (verifier != null) {
            try {
                return new EapMethod.Inner(
                        handler.stores()
                                        .verifiers()
                                        .get(verifier)
                                        .verifyPassword(user, password)
                                        .accepted()
                                ? AccessHandler.ACCEPT
                                : AccessHandler.REJECT,
                        null);
            } catch (StoreUnavailableException e) {
                once.warn(
                        "verifier-unavailable:" + verifier + ":" + e.getMessage(),
                        "verifier {} unavailable, requests are not answered: {}",
                        verifier,
                        e.getMessage());
                return new EapMethod.Inner(AccessHandler.DROP, null);
            }
        }
        return new EapMethod.Inner(
                handler.checkPassword(context, a.found(), user, a.passwords(), password)
                        ? AccessHandler.ACCEPT
                        : AccessHandler.REJECT,
                null);
    }
}
