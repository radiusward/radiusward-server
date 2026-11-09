/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.AccessRequests;
import io.radiusward.radius.codec.RadiusPacket;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * One Access-Request as a worker hands it to the {@link AccessHandler}: the validated request, its NAS entry,
 * credential helpers and the reply attributes being written. One instance per worker, reused for every request;
 * nothing in it outlives the call.
 */
public final class AccessContext {

    private final RadiusPacket request = new RadiusPacket();
    private final AccessRequests credentials = new AccessRequests();
    private final UnsafeBuffer replyBuffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final RadiusPacketEncoder reply = new RadiusPacketEncoder();
    private NasClient nas;
    private Object handlerState;
    private SessionLimits sessionLimits = SessionLimits.NONE;

    AccessContext() {}

    void reset(DirectBuffer buffer, int offset, int length, NasClient nas) {
        request.wrap(buffer, offset, length);
        this.nas = nas;
        reply.wrap(replyBuffer, 0).header(0, 0); // only the attributes after the header are used
    }

    /** The request, already validated: an Access-Request with a verified Message-Authenticator if it had one. */
    public RadiusPacket request() {
        return request;
    }

    /** The NAS entry the request came from (its secret, vendor, identity). */
    public NasClient nas() {
        return nas;
    }

    /** User-Password decryption, CHAP verification, method detection. */
    public AccessRequests credentials() {
        return credentials;
    }

    /**
     * Encoder for the reply attributes (Session-Timeout, Reply-Message, …); Message-Authenticator and Proxy-State
     * are added by the gateway.
     */
    public RadiusPacketEncoder reply() {
        return reply;
    }

    /**
     * What the handler keeps for this worker (its caches), {@code null} until it sets it. A context is only ever used
     * by its own worker thread, so this state needs no locking (single writer, like the agents' own tables).
     */
    public Object handlerState() {
        return handlerState;
    }

    public void handlerState(Object state) {
        this.handlerState = state;
    }

    /** Simultaneous use: reservations in the cluster, for this worker (ADR 0023). */
    public SessionLimits sessionLimits() {
        return sessionLimits;
    }

    void sessionLimits(SessionLimits limits) {
        this.sessionLimits = limits;
    }

    DirectBuffer replyBuffer() {
        return replyBuffer;
    }

    int replyAttributesLength() {
        return reply.length() - RadiusPacket.HEADER_LENGTH;
    }
}
