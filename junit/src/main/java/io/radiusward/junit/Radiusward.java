/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.junit;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Runs the test class against an embedded radiusward ({@code radiusward-embedded}): started before the tests, closed
 * after them (also after a failure), and given to the test methods as parameters: {@code EmbeddedRadiusward}, a {@code
 * RadiusClient} of the Access-Request port, a {@code @Accounting RadiusClient} of the Accounting-Request port.
 *
 * <pre>{@code
 * @Radiusward(users = "alice:secret")
 * class LoginTest {
 *     @Test
 *     void aliceLogsIn(RadiusClient nas) {
 *         assertThat(nas.pap("alice", "secret").orElseThrow().isAccept()).isTrue();
 *     }
 * }
 * }</pre>
 *
 * For the developer's own identity store, verifier or sink, register {@link RadiuswardExtension#configure} instead.
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@ExtendWith(RadiuswardExtension.class)
public @interface Radiusward {

    /** One server for all tests of the class (the default, about a second to start), or a fresh one per test. */
    Lifecycle lifecycle() default Lifecycle.PER_CLASS;

    /** Users as {@code name:password}; the password may contain {@code :}. */
    String[] users() default {};

    /** EAP methods to offer, e.g. {@code {"peap", "tls"}}; a TLS-based one gets the throwaway CA. */
    String[] eap() default {};

    /** Cluster members: 1, 3, 5 or 7. */
    int members() default 1;

    int radiusServers() default 1;

    /** Any setting as {@code key=value}. */
    String[] settings() default {};

    enum Lifecycle {
        PER_CLASS,
        PER_TEST
    }
}
