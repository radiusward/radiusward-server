/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing;

import io.radiusward.radius.codec.RadiusAuthenticator;
import io.radiusward.radius.codec.RadiusCode;
import io.radiusward.radius.codec.RadiusPacketEncoder;
import io.radiusward.server.EventKeys;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Accounting-Requests for tests, signed with the shared secret: {@code AccountingRequest.of(1, START).session("s-1")
 * .build()}. Event-Timestamp is a fixed 2026 date unless set; Interim-Update and Stop carry Acct-Session-Time and
 * Acct-Input-Octets (a thousand per second).
 */
public final class AccountingRequest {

    public static final int START = 1;
    public static final int STOP = 2;
    public static final int INTERIM = 3;
    /** Event-Timestamp unless one is set: 2026-05-28. */
    public static final long EVENT_TIMESTAMP = 1_780_000_000L;

    private final int id;
    private final int status;
    private String sessionId;
    private long sessionTime;
    private long eventTimestamp = EVENT_TIMESTAMP;
    private int delay;
    private String nasIdentifier;
    private byte[] secret = FakeNas.SECRET;
    private final List<byte[]> extra = new ArrayList<>();

    private AccountingRequest(int id, int status) {
        this.id = id;
        this.status = status;
    }

    /** A request with this identifier and Acct-Status-Type. */
    public static AccountingRequest of(int id, int status) {
        return new AccountingRequest(id, status);
    }

    /** The usual request: Acct-Session-Id, and the session time for Interim-Update and Stop. */
    public static byte[] request(int id, int status, String sessionId, long sessionTime) {
        return of(id, status).session(sessionId).sessionTime(sessionTime).build();
    }

    /** As above, with this Event-Timestamp. */
    public static byte[] request(int id, int status, String sessionId, long sessionTime, long eventTimestamp) {
        return of(id, status)
                .session(sessionId)
                .sessionTime(sessionTime)
                .eventTimestamp(eventTimestamp)
                .build();
    }

    public AccountingRequest session(String acctSessionId) {
        this.sessionId = acctSessionId;
        return this;
    }

    public AccountingRequest sessionTime(long seconds) {
        this.sessionTime = seconds;
        return this;
    }

    public AccountingRequest eventTimestamp(long epochSeconds) {
        this.eventTimestamp = epochSeconds;
        return this;
    }

    /** Acct-Delay-Time, left out when 0. */
    public AccountingRequest delay(int seconds) {
        this.delay = seconds;
        return this;
    }

    /** NAS-Identifier: a device behind a NAS entry that tells devices apart. */
    public AccountingRequest nasIdentifier(String nasIdentifier) {
        this.nasIdentifier = nasIdentifier;
        return this;
    }

    public AccountingRequest secret(byte[] secret) {
        this.secret = secret.clone();
        return this;
    }

    /** Another text attribute. */
    public AccountingRequest attribute(int type, String value) {
        byte[] v = value.getBytes(StandardCharsets.UTF_8);
        byte[] a = new byte[2 + v.length];
        a[0] = (byte) type;
        a[1] = (byte) a.length;
        System.arraycopy(v, 0, a, 2, v.length);
        extra.add(a);
        return this;
    }

    /** Another 32-bit attribute, such as NAS-IP-Address. */
    public AccountingRequest uint32(int type, long value) {
        extra.add(new byte[] {
            (byte) type, 6, (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
        });
        return this;
    }

    public byte[] build() {
        UnsafeBuffer buffer = new UnsafeBuffer(new byte[4096]);
        RadiusPacketEncoder enc = new RadiusPacketEncoder().wrap(buffer, 0);
        enc.header(RadiusCode.ACCOUNTING_REQUEST, id).uint32(40, status);
        if (nasIdentifier != null) {
            enc.attribute(32, nasIdentifier);
        }
        if (sessionId != null) {
            enc.attribute(44, sessionId);
        }
        enc.uint32(55, eventTimestamp);
        if (status == STOP || status == INTERIM) {
            enc.uint32(46, sessionTime).uint32(42, sessionTime * 1000);
        }
        if (delay > 0) {
            enc.uint32(41, delay);
        }
        for (byte[] a : extra) {
            enc.attribute(a[0] & 0xFF, new UnsafeBuffer(a), 2, a.length - 2);
        }
        int length = enc.finish();
        new RadiusAuthenticator().signAccountingRequest(buffer, 0, length, -1, secret);
        return Arrays.copyOf(buffer.byteArray(), length);
    }

    /** The cluster's key of a session of {@link LocalCluster}'s NAS entry. */
    public static long[] sessionKey(String acctSessionId) {
        return sessionKey(acctSessionId, "");
    }

    /** The key of a device's session when the NAS entry tells devices apart by NAS-Identifier. */
    public static long[] sessionKey(String acctSessionId, String nasIdentifier) {
        EventKeys keys = new EventKeys();
        UnsafeBuffer id = new UnsafeBuffer(acctSessionId.getBytes(StandardCharsets.US_ASCII));
        UnsafeBuffer device = new UnsafeBuffer(nasIdentifier.getBytes(StandardCharsets.US_ASCII));
        keys.compute(LocalCluster.NAS_ID, device, device.capacity(), 0, 0, 0, 0, 0, 0, id, 0, id.capacity());
        return new long[] {keys.sessionHi(), keys.sessionLo()};
    }
}
