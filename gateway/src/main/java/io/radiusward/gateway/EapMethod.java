/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import java.util.List;

/**
 * One EAP method of one conversation (5.7, ADR 0026): started with the peer's identity, then given each response until
 * it succeeds or fails. Stateful, used by one worker at a time (the conversation table hands it out).
 */
interface EapMethod {

    /** What the user record offers a method: its check items (passwords) and whether the store allows cleartext use. */
    record Credentials(List<AttributeItem> passwords, boolean cleartextAllowed) {}

    /** The next step: another request to the peer, success (with the MSK if the method derives one), or failure. */
    record Step(byte[] request, boolean success, byte[] msk) {

        static Step next(byte[] typeData) {
            return new Step(typeData, false, null);
        }

        static Step succeeded(byte[] msk) {
            return new Step(null, true, msk);
        }

        static final Step FAILED = new Step(null, false, null);

        boolean done() {
            return request == null;
        }
    }

    /** The EAP type number. */
    int type();

    /** The first request's type data. */
    Step start(int identifier, Credentials credentials);

    /**
     * @param identifier the identifier of the request this answers
     * @param data the response's type data
     */
    Step process(int identifier, byte[] data, Credentials credentials);
}
