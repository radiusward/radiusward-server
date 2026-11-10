/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.AccessResponses;
import io.radiusward.radius.codec.RadiusAuthenticator;
import org.agrona.concurrent.Agent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Decides Access-Requests taken from {@link AccessSlots#work}: calls the {@link AccessHandler}, builds the signed
 * reply into the slot and hands it back through {@link AccessSlots#done}. Several workers share the queue; each owns
 * its context and codec objects. A handler that throws or returns {@link AccessHandler#DROP} leaves the request
 * unanswered.
 */
final class AccessWorker implements Agent {

    private static final Logger LOG = LogManager.getLogger(AccessWorker.class);

    private final int index;
    private final AccessSlots slots;
    private final AccessHandler handler;
    private final AuthStats stats;
    private final AccessContext context = new AccessContext();
    private final AccessResponses responses = new AccessResponses(new RadiusAuthenticator());
    private long errors;

    AccessWorker(int index, AccessSlots slots, AccessHandler handler, AuthStats stats) {
        this(index, slots, handler, stats, SessionLimits.NONE);
    }

    AccessWorker(int index, AccessSlots slots, AccessHandler handler, AuthStats stats, SessionLimits limits) {
        context.sessionLimits(limits);
        this.index = index;
        this.slots = slots;
        this.handler = handler;
        this.stats = stats;
    }

    @Override
    public int doWork() {
        Integer id = slots.work.poll();
        if (id == null) {
            return 0;
        }
        int slot = id;
        int length;
        try {
            length = decide(slot);
        } catch (RuntimeException e) { // the handler, or a reply larger than 4096 bytes
            stats.increment(AuthStats.Counter.HANDLER_ERRORS);
            if (errors++ % 1000 == 0) { // never a log line per request
                LOG.warn("access request failed ({} times on worker {}): {}", errors, index, e.toString());
            }
            length = 0;
        }
        slots.replyLength[slot] = length;
        while (!slots.done.offer(id)) {
            Thread.onSpinWait(); // the done queue has a place for every slot: only momentarily contended
        }
        return 1;
    }

    private int decide(int slot) {
        NasClient nas = slots.nas[slot];
        context.reset(slots.requests, AccessSlots.requestOffset(slot), slots.requestLength[slot], nas);
        Tracer t = tracer;
        Tracer.Trace trace = t == null ? null : t.start(context.request(), nas);
        context.trace(trace);
        int code = handler.handle(context);
        if (trace != null) {
            t.finish(trace, context.request(), nas, code, context.replyBuffer(), context.replyAttributesLength());
        }
        AuthLog log = authLog;
        if (log != null && (code == AccessHandler.ACCEPT || code == AccessHandler.REJECT)) {
            log.record(new AuthLog.Entry(
                    java.time.Instant.now(),
                    nas.name(),
                    text(context.request(), 1),
                    text(context.request(), 31),
                    code == AccessHandler.ACCEPT,
                    code == AccessHandler.REJECT
                            ? (context.reason() != null
                                    ? withoutTrailingColon(context.reason())
                                    : "credentials or method rejected")
                            : null));
        }
        switch (code) {
            case AccessHandler.ACCEPT -> stats.increment(AuthStats.Counter.ACCEPTED);
            case AccessHandler.REJECT -> stats.increment(AuthStats.Counter.REJECTED);
            case AccessHandler.CHALLENGE -> stats.increment(AuthStats.Counter.CHALLENGED);
            default -> {
                stats.increment(AuthStats.Counter.DROPPED);
                return 0;
            }
        }
        return responses.encode(
                context.request(),
                code,
                context.replyBuffer(),
                io.radiusward.radius.codec.RadiusPacket.HEADER_LENGTH,
                context.replyAttributesLength(),
                slots.replyViews[slot],
                0,
                nas.secret());
    }

    private volatile Tracer tracer;
    private volatile AuthLog authLog;

    /** The authentication log (ADR 0058); {@code null}: none. */
    void authLog(AuthLog log) {
        this.authLog = log;
    }

    /** A recorded cause such as {@code "user not in any store: "} without its trailing colon and spaces. */
    static String withoutTrailingColon(String reason) {
        int end = reason.length();
        while (end > 0 && (reason.charAt(end - 1) == ':' || Character.isWhitespace(reason.charAt(end - 1)))) {
            end--;
        }
        return reason.substring(0, end);
    }

    private static String text(io.radiusward.radius.codec.RadiusPacket request, int type) {
        int at = request.findAttribute(type);
        return at < 0
                ? null
                : request.buffer()
                        .getStringWithoutLengthUtf8(at + 2, (request.buffer().getByte(at + 1) & 0xFF) - 2);
    }

    /** Per-request traces (ADR 0052); {@code null}: none. */
    void tracer(Tracer tracer) {
        this.tracer = tracer;
    }

    @Override
    public String roleName() {
        return "access-worker-" + index;
    }
}
