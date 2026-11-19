/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.junit;

import io.radiusward.client.RadiusClient;
import io.radiusward.embedded.EmbeddedRadiusward;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.platform.commons.support.AnnotationSupport;

/**
 * Starts an embedded radiusward for a test class or a test and closes it afterwards; resolves {@link EmbeddedRadiusward}
 * and {@link RadiusClient} parameters (clients are closed after their test). Used through {@link Radiusward}, or
 * registered with the developer's own setup:
 *
 * <pre>{@code
 * @RegisterExtension
 * static RadiuswardExtension radius = RadiuswardExtension.configure(b -> b
 *         .identityStore(new MyUsers())
 *         .sink(new MyBillingSink()));          // static: one server per class; an instance field: one per test
 * }</pre>
 *
 * Test classes running in parallel each get their own server, directory and ports.
 */
public final class RadiuswardExtension implements BeforeAllCallback, BeforeEachCallback, ParameterResolver {

    private static final ExtensionContext.Namespace NAMESPACE =
            ExtensionContext.Namespace.create(RadiuswardExtension.class);
    private static final String SERVER = "server";

    private final Consumer<EmbeddedRadiusward.Builder> setup;

    /** For {@link Radiusward}: the settings come from the annotation. */
    public RadiuswardExtension() {
        this.setup = null;
    }

    private RadiuswardExtension(Consumer<EmbeddedRadiusward.Builder> setup) {
        this.setup = setup;
    }

    /**
     * An extension that sets up the builder in code (the developer's own stores, verifier, sinks, SIM users, ...),
     * after what a {@link Radiusward} annotation on the class says.
     */
    public static RadiuswardExtension configure(Consumer<EmbeddedRadiusward.Builder> setup) {
        return new RadiuswardExtension(Objects.requireNonNull(setup));
    }

    /** The server of the current test class or test, as a parameter would give it. */
    public static EmbeddedRadiusward server(ExtensionContext context) {
        EmbeddedRadiusward server = context.getStore(NAMESPACE).get(SERVER, EmbeddedRadiusward.class);
        if (server == null) {
            throw new IllegalStateException("no embedded radiusward for " + context.getDisplayName());
        }
        return server;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        if (lifecycle(context) == Radiusward.Lifecycle.PER_CLASS && !hasServer(context)) {
            start(context);
        }
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        // per test by choice, or an extension in an instance field, which JUnit only sees for each test
        if (!hasServer(context)) {
            start(context);
        }
    }

    private static boolean hasServer(ExtensionContext context) {
        return context.getStore(NAMESPACE).get(SERVER) != null;
    }

    private void start(ExtensionContext context) {
        EmbeddedRadiusward.Builder builder = EmbeddedRadiusward.builder();
        annotation(context).ifPresent(a -> apply(a, builder));
        if (setup != null) {
            setup.accept(builder);
        }
        // the store closes it when its class or test is done, also after a failure
        context.getStore(NAMESPACE).put(SERVER, builder.start());
    }

    static void apply(Radiusward a, EmbeddedRadiusward.Builder builder) {
        builder.members(a.members()).radiusServers(a.radiusServers());
        for (String user : a.users()) {
            int colon = user.indexOf(':');
            if (colon <= 0) {
                throw new IllegalArgumentException("@Radiusward users: name:password, got \"" + user + "\"");
            }
            builder.user(user.substring(0, colon), user.substring(colon + 1));
        }
        if (a.eap().length > 0) {
            builder.eap(a.eap());
        }
        for (String setting : a.settings()) {
            int equals = setting.indexOf('=');
            if (equals <= 0) {
                throw new IllegalArgumentException("@Radiusward settings: key=value, got \"" + setting + "\"");
            }
            builder.setting(
                    setting.substring(0, equals).trim(),
                    setting.substring(equals + 1).trim());
        }
    }

    private static Optional<Radiusward> annotation(ExtensionContext context) {
        return context.getTestClass().flatMap(c -> AnnotationSupport.findAnnotation(c, Radiusward.class));
    }

    private static Radiusward.Lifecycle lifecycle(ExtensionContext context) {
        return annotation(context).map(Radiusward::lifecycle).orElse(Radiusward.Lifecycle.PER_CLASS);
    }

    @Override
    public boolean supportsParameter(ParameterContext parameter, ExtensionContext context) {
        Class<?> type = parameter.getParameter().getType();
        return type == EmbeddedRadiusward.class || type == RadiusClient.class;
    }

    @Override
    public Object resolveParameter(ParameterContext parameter, ExtensionContext context) {
        if (!hasServer(context)) {
            throw new ParameterResolutionException(
                    "no embedded radiusward yet: a parameter of a @BeforeAll method needs the default lifecycle");
        }
        EmbeddedRadiusward server = server(context);
        if (parameter.getParameter().getType() == EmbeddedRadiusward.class) {
            return server;
        }
        RadiusClient client = parameter.isAnnotated(Accounting.class) ? server.accountingClient() : server.client();
        // closed with the test (or the class, for a @BeforeAll parameter)
        context.getStore(NAMESPACE).put(new Object(), client);
        return client;
    }
}
