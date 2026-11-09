/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.sql;

import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.StoreContext;

/** {@code auth.store.<name>.type = sql}. */
public final class SqlStoreProvider implements IdentityStoreProvider {

    @Override
    public String type() {
        return "sql";
    }

    @Override
    public IdentityStore create(StoreContext context) {
        return new SqlStore(context);
    }
}
