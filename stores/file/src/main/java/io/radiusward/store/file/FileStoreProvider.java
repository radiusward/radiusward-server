/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.store.file;

import io.radiusward.auth.IdentityStore;
import io.radiusward.auth.IdentityStoreProvider;
import io.radiusward.auth.StoreContext;

/** {@code auth.store.<name>.type = file}. */
public final class FileStoreProvider implements IdentityStoreProvider {

    @Override
    public String type() {
        return "file";
    }

    @Override
    public IdentityStore create(StoreContext context) {
        return new FileStore(context);
    }
}
