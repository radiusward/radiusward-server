/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

/**
 * Creates identity stores of one type ({@code auth.store.<name>.type}); found with {@link java.util.ServiceLoader}
 * on the class path and in the plug-ins directory ({@code META-INF/services/io.radiusward.auth.IdentityStoreProvider}).
 */
public interface IdentityStoreProvider {

    /** The {@code type} value this provider serves, e.g. {@code sql}, {@code file}. */
    String type();

    IdentityStore create(StoreContext context);
}
