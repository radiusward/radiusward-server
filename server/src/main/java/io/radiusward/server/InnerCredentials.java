/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.CredentialVerifier;
import io.radiusward.auth.Md4;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.eap.MsChap;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

/**
 * The credentials of a tunnel's inner user (PEAP, TTLS, TEAP: PAP, CHAP, MS-CHAP, MS-CHAPv2), checked like the same
 * methods outside a tunnel: the user looked up and authorized by the {@link UserDirectory}, then a credential
 * verifier or the stored credentials, or, for a proxied realm, its home server (ADR 0044).
 */
final class InnerCredentials {

    private final Supplier<AuthStores> stores; // replaced by a reload (ADR 0054)
    private final Supplier<InnerProxy> proxy;
    private final UserDirectory directory;
    private final MsChapAuthenticator msChap;
    private final PasswordChecks passwords;
    private final OnceLogger once;

    InnerCredentials(
            Supplier<AuthStores> stores,
            Supplier<InnerProxy> proxy,
            UserDirectory directory,
            MsChapAuthenticator msChap,
            PasswordChecks passwords,
            OnceLogger once) {
        this.directory = directory;
        this.msChap = msChap;
        this.stores = stores;
        this.proxy = proxy;
        this.passwords = passwords;
        this.once = once;
    }

    /** A home server's verdict on the inner user: its reply kept for our Accept, the tunnel not remembered. */
    private EapMethod.Inner proxied(AuthRequest auth, InnerProxy.Result r) {
        AccessContext context = auth.context();
        EapConversations.Conversation c = auth.eap.conversation;
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
    EapMethod.Inner msChapV2(AuthRequest auth, String user, EapMethod.MsChapV2 exchange) {
        AccessContext context = auth.context();
        InnerProxy home = proxy.get();
        if (home != null && home.realm(user) != null) {
            return proxied(auth, home.msChapV2(user, exchange));
        }
        return msChap(auth, user, exchange.challengeHash(), exchange.ntResponse(), true);
    }

    /**
     * CHAP inside a tunnel: only with the cleartext password of a store that allows CHAP, as outside it; verifiers
     * cannot answer CHAP.
     */
    EapMethod.Inner chap(AuthRequest auth, String user, int identifier, byte[] challenge, byte[] response) {
        AccessContext context = auth.context();
        InnerProxy home = proxy.get();
        if (home != null && home.realm(user) != null) {
            return proxied(auth, home.chap(user, identifier, challenge, response));
        }
        UserDirectory.Authorization a = directory.authorize(auth, user, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        if (a.authType().equalsIgnoreCase("Accept")) {
            return new EapMethod.Inner(AccessHandler.ACCEPT, null);
        }
        if (!stores.get().chap().getOrDefault(a.found().store(), false)) {
            once.warn(
                    "chap:" + a.found().store(),
                    "CHAP request for store {}, which does not allow CHAP"
                            + " (auth.store.<name>.chap = true needs cleartext passwords): rejected",
                    a.found().store());
            return new EapMethod.Inner(AccessHandler.REJECT, null);
        }
        for (AttributeItem p : a.passwords()) {
            if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT)) {
                boolean matches =
                        EapMd5.chapMatches(identifier, p.value().getBytes(StandardCharsets.UTF_8), challenge, response);
                return new EapMethod.Inner(matches ? AccessHandler.ACCEPT : AccessHandler.REJECT, null);
            }
        }
        return new EapMethod.Inner(AccessHandler.REJECT, null);
    }

    /** MS-CHAP inside a tunnel; {@code challenge} is the v2 challenge hash or the v1 challenge (both 8 bytes). */
    EapMethod.Inner msChap(AuthRequest auth, String user, byte[] challenge, byte[] ntResponse, boolean v2) {
        AccessContext context = auth.context();
        UserDirectory.Authorization a = directory.authorize(auth, user, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        String verifier = passwords.verifierFor(a.authType(), a.found().store(), a.passwords());
        if (verifier != null) {
            try {
                CredentialVerifier.Result r =
                        stores.get().verifiers().get(verifier).verifyMsChap(user, challenge, ntResponse, v2);
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
        byte[] ntHash = msChap.localNtHash(a.found(), a.passwords());
        if (ntHash == null
                || !java.security.MessageDigest.isEqual(MsChap.challengeResponse(challenge, ntHash), ntResponse)) {
            return new EapMethod.Inner(AccessHandler.REJECT, null);
        }
        return new EapMethod.Inner(AccessHandler.ACCEPT, Md4.digest(ntHash));
    }

    /** A password inside a tunnel (TTLS/PAP): the inner user looked up, then a verifier or the stored credentials. */
    EapMethod.Inner password(AuthRequest auth, String user, byte[] password) {
        AccessContext context = auth.context();
        InnerProxy home = proxy.get();
        if (home != null && home.realm(user) != null) {
            return proxied(auth, home.password(user, password));
        }
        UserDirectory.Authorization a = directory.authorize(auth, user, false);
        if (a.code() != AccessHandler.ACCEPT) {
            return new EapMethod.Inner(a.code(), null);
        }
        if (a.authType().equalsIgnoreCase("Accept")) {
            return new EapMethod.Inner(AccessHandler.ACCEPT, null);
        }
        String verifier = passwords.verifierFor(a.authType(), a.found().store(), a.passwords());
        if (verifier != null) {
            try {
                return new EapMethod.Inner(
                        stores.get()
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
                passwords.checkPassword(auth, a.found(), user, a.passwords(), password)
                        ? AccessHandler.ACCEPT
                        : AccessHandler.REJECT,
                null);
    }
}
