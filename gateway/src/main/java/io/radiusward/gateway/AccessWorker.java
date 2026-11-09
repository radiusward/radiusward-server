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
        int code = handler.handle(context);
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

    @Override
    public String roleName() {
        return "access-worker-" + index;
    }
}
