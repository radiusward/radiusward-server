/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.StoreUnavailableException;
import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * EAP in RADIUS (RFC 3748, RFC 3579; ADR 0026): finds the conversation of an EAP response by its State, runs a round
 * of its method (started after the Identity response, switched on a Nak), and keeps the conversation for the next
 * round. A tunnel's inner user is authorized in place of the outer one (ADR 0029), or answered by its realm's home
 * server (ADR 0044). On success the reply carries EAP-Success and the MSK as MS-MPPE keys.
 */
final class EapAuthenticator {

    /** {@link #authenticate}: the home server of the inner user's realm answered; its reply is already written. */
    static final UserDirectory.Authorization ANSWERED = UserDirectory.Authorization.of(AccessHandler.ACCEPT);

    private final Supplier<AuthStores> stores; // replaced by a reload (ADR 0054)
    private final Supplier<InnerProxy> innerProxy;
    private final LongSupplier clockMillis;
    private final AuthMetrics metrics;
    private final UserDirectory directory;
    private final InnerCredentials inner;
    private final MsChapAuthenticator msChap;
    private final OnceLogger once;
    private final EapConversations conversations;

    EapAuthenticator(
            Supplier<AuthStores> stores,
            Supplier<InnerProxy> innerProxy,
            LongSupplier clockMillis,
            AuthMetrics metrics,
            UserDirectory directory,
            InnerCredentials inner,
            MsChapAuthenticator msChap,
            OnceLogger once) {
        this.stores = stores;
        this.innerProxy = innerProxy;
        this.clockMillis = clockMillis;
        this.metrics = metrics;
        this.directory = directory;
        this.inner = inner;
        this.msChap = msChap;
        this.once = once;
        this.conversations = new EapConversations(stores.get().eap().conversations());
    }

    /**
     * A round of the conversation for the authorized outer user {@code a}: {@link AccessHandler#CHALLENGE} (with the
     * next request), {@link AccessHandler#REJECT} or {@link AccessHandler#DROP} as {@code Authorization.of(code)};
     * when the method succeeded, the authorization to go on with (the inner user's for a tunnel), or {@link #ANSWERED}.
     */
    UserDirectory.Authorization authenticate(AuthRequest auth, UserDirectory.Authorization a) {
        int round = round(auth, a.found(), a.authType(), a.passwords());
        if (round != AccessHandler.ACCEPT) {
            return UserDirectory.Authorization.of(round);
        }
        EapConversations.Conversation c = auth.eap.conversation;
        String innerUser = c.method == null ? null : c.method.innerIdentity();
        InnerProxy p = innerProxy.get();
        if (innerUser != null && p != null && p.realm(innerUser) != null) {
            if (c.proxiedReply == null) {
                return UserDirectory.Authorization.of(AccessHandler.REJECT); // no verdict from it in this conversation
            }
            writeSuccess(auth, AccessRequests.METHOD_EAP);
            auth.context().reply().rawAttributes(new UnsafeBuffer(c.proxiedReply), 0, c.proxiedReply.length);
            return ANSWERED;
        }
        if (innerUser != null) { // a tunnel: the inner user is the one authorized (ADR 0029)
            return directory.authorize(auth, innerUser, c.method.innerOptional());
        }
        return a;
    }

    private static final int STATE = 24;

    /**
     * Reads the EAP response and finds its conversation: a new one for an Identity response without State, the one
     * the State names otherwise. {@link #ACCEPT} to go on; a malformed packet is discarded ({@link #DROP}), an
     * unknown or used State is rejected.
     */
    int begin(AuthRequest auth) {
        AccessContext context = auth.context();
        RadiusPacket request = context.request();
        EapPacket eap = EapPacket.from(request);
        if (eap == null || eap.code() != EapPacket.CODE_RESPONSE) {
            return AccessHandler.DROP; // RFC 3579 §2.6.2: silently discard
        }
        AuthRequest.EapRound round = auth.eap;
        round.packet = eap;
        int at = request.findAttribute(STATE);
        if (at < 0) {
            if (eap.type() != EapPacket.TYPE_IDENTITY) {
                return AccessHandler.REJECT;
            }
            String identity = new String(eap.data(), StandardCharsets.UTF_8)
                    .replace("\0", "")
                    .trim();
            if (identity.isEmpty()) {
                return AccessHandler.REJECT;
            }
            round.conversation = new EapConversations.Conversation(context.nas().name(), identity);
            return AccessHandler.ACCEPT;
        }
        byte[] state = new byte[(request.buffer().getByte(at + 1) & 0xFF) - 2];
        request.buffer().getBytes(at + 2, state);
        round.state = state;
        round.conversation = conversations.take(state, context.nas().name(), clockMillis.getAsLong());
        return round.conversation == null ? AccessHandler.REJECT : AccessHandler.ACCEPT;
    }

    /**
     * One round of the conversation's method: starts it after the Identity response, follows a Nak, or gives the
     * method the peer's response. Returns {@link #CHALLENGE} with the next request and a new State, {@link #ACCEPT}
     * when the method succeeded, {@link #REJECT} when it failed, {@link #DROP} when the table is full or the response
     * answers another request.
     */
    private int round(AuthRequest auth, UserDirectory.Found found, String authType, List<AttributeItem> passwords) {
        AccessContext context = auth.context();
        AuthRequest.EapRound round = auth.eap;
        EapPacket eap = round.packet;
        EapConversations.Conversation c = round.conversation;
        if (authType.equalsIgnoreCase("Accept")) {
            return AccessHandler.ACCEPT; // no credential to check: EAP-Success right away
        }
        AuthStores stores = this.stores.get();
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
                return AccessHandler.REJECT; // not reached: configuration refuses TLS methods without a certificate
            }
            step = c.method.start(eap.identifier() + 1, credentials);
        } else if (eap.identifier() != c.identifier) {
            return AccessHandler.DROP; // a response to an earlier request
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
                return AccessHandler.REJECT; // nothing both sides support, or a Nak after the method began
            }
            c.method = offered;
            step = c.method.start(eap.identifier() + 1, credentials);
        } else if (eap.type() != c.method.type()) {
            return AccessHandler.REJECT;
        } else {
            step = c.method.process(eap.identifier(), eap.data(), credentials);
        }
        if (step.unavailable()) {
            metrics.eapOutcome(c.method.type(), AuthMetrics.STORE_UNAVAILABLE);
            // the inner credential cannot be checked now: keep the conversation for the peer's retransmission
            if (round.state != null) {
                conversations.putBack(round.state, c, clockMillis.getAsLong());
            }
            return AccessHandler.DROP;
        }
        if (++c.rounds > stores.eap().maxRounds()) {
            metrics.eapOutcome(c.method.type(), AuthMetrics.TOO_MANY_ROUNDS);
            return AccessHandler.REJECT;
        }
        if (step.done()) {
            round.msk = step.msk();
            metrics.eapOutcome(c.method.type(), step.success() ? AuthMetrics.SUCCEEDED : AuthMetrics.FAILED);
            return step.success() ? AccessHandler.ACCEPT : AccessHandler.REJECT;
        }
        long now = clockMillis.getAsLong();
        c.identifier = (eap.identifier() + 1) & 0xFF;
        c.expires = now + stores.eap().timeout().toMillis();
        byte[] state = conversations.put(c, now);
        if (state == null) {
            once.warn("eap-full", "EAP conversations full (auth.eap.conversations): new rounds are not answered", null);
            return AccessHandler.DROP;
        }
        EapPacket.request(c.identifier, c.method.type(), step.request()).writeTo(context.reply());
        context.reply().attribute(STATE, state);
        return AccessHandler.CHALLENGE;
    }

    /** Whether this conversation's method (or the one it will start, or a Nak asks for) needs no store entry. */
    boolean outerOptional(AuthRequest auth) {
        AuthStores stores = this.stores.get();
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
    void writeSuccess(AuthRequest auth, int method) {
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
    int conversations() {
        return conversations.size();
    }

    /** A SIM subscriber's check items by IMSI, from the stores of this NAS entry; keys are checked here once. */
    private EapMethod.Subscriber simSubscriber(AuthRequest auth, String imsi) {
        AccessContext context = auth.context();
        UserDirectory.Found found;
        try {
            found = directory.find(auth.caches(), context.nas().name(), imsi);
        } catch (StoreUnavailableException e) {
            once.warn("unavailable:" + e.getMessage(), "identity store unavailable, requests are not answered: {}", e);
            StoreAccessHandler.because(context, "identity store unavailable: ", e.getMessage());
            return new EapMethod.Subscriber(AccessHandler.DROP, List.of());
        }
        if (found == null) {
            StoreAccessHandler.because(context, "SIM subscriber not in any store: ", imsi);
            return new EapMethod.Subscriber(AccessHandler.REJECT, List.of());
        }
        try {
            if (!SimSubscriber.of(found.user().check()).gsm()) {
                once.warn(
                        "sim-keys:" + found.store(),
                        "store {}: SIM subscribers need SIM-Ki and SIM-OPc (or "
                                + "SIM-OP), or three stored triplets; COMP128 is not supported",
                        found.store());
                StoreAccessHandler.because(context, "no usable SIM keys for ", imsi);
                return new EapMethod.Subscriber(AccessHandler.REJECT, List.of());
            }
        } catch (IllegalArgumentException e) {
            once.warn(
                    "sim-keys-bad:" + found.store(), "store {}: {}", found.store(), e.getMessage()); // never the value
            StoreAccessHandler.because(context, "SIM keys not understood for ", imsi);
            return new EapMethod.Subscriber(AccessHandler.REJECT, List.of());
        }
        return new EapMethod.Subscriber(AccessHandler.ACCEPT, found.user().check());
    }
}
