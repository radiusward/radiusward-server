/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.export;

import java.util.Objects;
import java.util.function.Supplier;

/**
 * Creates the sinks of one type ({@code sink.<name>.type}): registered in
 * {@code META-INF/services/io.radiusward.export.SinkProvider} on the class path or in {@code export.plugins.dir}, or
 * given in code to a member that is started in code (an embedded one, a test), e.g. with {@link #of}.
 */
public interface SinkProvider {

    /** The value of {@code sink.<name>.type}, e.g. {@code postgres}, {@code file}. */
    String type();

    /** Called once for each {@code sink.<name>} of this type when the member starts; the exporter closes it at stop. */
    AccountingSink create();

    /** A provider in code: {@code create} returns what {@code factory} supplies. */
    static SinkProvider of(String type, Supplier<AccountingSink> factory) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(factory, "factory");
        return new SinkProvider() {
            @Override
            public String type() {
                return type;
            }

            @Override
            public AccountingSink create() {
                return Objects.requireNonNull(factory.get(), "the factory of " + type + " returned null");
            }
        };
    }
}
