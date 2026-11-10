/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.cluster.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

/** The attributes that name a session to its NAS (ADR 0036). */
class SessionIdentityTest {

    private final UnsafeBuffer out = new UnsafeBuffer(new byte[SessionStore.IDENTITY_SIZE]);

    static byte[] attr(int type, String value) {
        byte[] v = value.getBytes(StandardCharsets.UTF_8);
        byte[] a = new byte[2 + v.length];
        a[0] = (byte) type;
        a[1] = (byte) a.length;
        System.arraycopy(v, 0, a, 2, v.length);
        return a;
    }

    static byte[] attrs(byte[]... list) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (byte[] a : list) {
            b.writeBytes(a);
        }
        return b.toByteArray();
    }

    @Test
    void takesTheIdentifyingAttributesInOrderOfImportance() {
        byte[] raw = attrs(
                attr(40, "x"), // Acct-Status-Type: not identifying
                attr(31, "aa-bb-cc-dd-ee-ff"),
                attr(1, "alice"),
                attr(44, "0000ABCD"),
                new byte[] {4, 6, 10, 0, 0, 1}, // NAS-IP-Address
                new byte[] {8, 6, 10, 9, 0, 7}, // Framed-IP-Address
                attr(1, "second")); // only the first of each type
        int n = SessionIdentity.extract(new UnsafeBuffer(raw), 0, raw.length, out, 0);
        assertThat(out.getByte(0)).as("Acct-Session-Id first").isEqualTo((byte) 44);
        assertThat(SessionIdentity.string(out, 0, n, 44)).isEqualTo("0000ABCD");
        assertThat(SessionIdentity.string(out, 0, n, 1)).isEqualTo("alice");
        assertThat(SessionIdentity.string(out, 0, n, 31)).isEqualTo("aa-bb-cc-dd-ee-ff");
        assertThat(SessionIdentity.string(out, 0, n, 40)).isNull();
        assertThat(n).isEqualTo(10 + 7 + 6 + 6 + 19);
    }

    @Test
    void stopsWhereTheIdentityIsFullOrTheSectionBroken() {
        byte[] raw = attrs(attr(44, "s".repeat(40)), attr(1, "u".repeat(20)), new byte[] {4, 6, 10, 0, 0, 1});
        int n = SessionIdentity.extract(new UnsafeBuffer(raw), 0, raw.length, out, 0);
        assertThat(n).as("the User-Name does not fit, the NAS-IP-Address does").isEqualTo(42 + 6);
        assertThat(SessionIdentity.string(out, 0, n, 1)).isNull();

        byte[] broken = attrs(attr(44, "abc"), new byte[] {1, 40, 'x'});
        assertThat(SessionIdentity.extract(new UnsafeBuffer(broken), 0, broken.length, out, 0))
                .isEqualTo(5);
        assertThat(SessionIdentity.extract(new UnsafeBuffer(new byte[] {1, 1}), 0, 2, out, 0))
                .isZero();
    }
}
