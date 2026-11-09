/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

import java.util.Optional;

/**
 * Where users come from (Phase 5, ADR 0021). A store only <b>looks up</b>: the gateway verifies credentials,
 * evaluates check items and encodes reply attributes, so every store gets the same correct crypto.
 *
 * <p>Called on gateway worker threads, concurrently: implementations are thread-safe and bound their own waiting
 * (connection and query timeouts below the NAS timeout).
 */
public interface IdentityStore extends AutoCloseable {

    /**
     * The user, or empty if this store does not know {@code userName}.
     *
     * @throws StoreUnavailableException when the store cannot answer now (the request is then left unanswered, so
     *     the NAS retries or tries another server — an outage never becomes an Accept or a Reject)
     */
    Optional<UserRecord> lookup(String userName) throws StoreUnavailableException;

    @Override
    void close();
}
