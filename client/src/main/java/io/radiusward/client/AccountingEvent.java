/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * One accounting event as a NAS reports it: the attributes of an Accounting-Request, fixed when the event happened
 * (Event-Timestamp included), so the same event can be sent again. {@link #delay} gives the NAS's retransmission of
 * it: the same event with Acct-Delay-Time, which a RADIUS server counts once. Immutable; {@link RadiusClient#send(
 * AccountingEvent)} sends it with the next identifier.
 *
 * <p>Sessions make events with {@link AccountingSession}; {@link #accountingOn} and {@link #accountingOff} are the
 * NAS-wide ones.
 */
public final class AccountingEvent {

    public static final int START = 1;
    public static final int STOP = 2;
    public static final int INTERIM_UPDATE = 3;
    public static final int ACCOUNTING_ON = 7;
    public static final int ACCOUNTING_OFF = 8;

    private final int statusType;
    private final List<byte[]> attributes; // whole attributes, in order
    private final long delaySeconds; // -1: no Acct-Delay-Time

    private AccountingEvent(int statusType, List<byte[]> attributes, long delaySeconds) {
        this.statusType = statusType;
        this.attributes = List.copyOf(attributes);
        this.delaySeconds = delaySeconds;
    }

    /** An event of any Acct-Status-Type with these attributes after it (each whole: type, length, value). */
    public static AccountingEvent of(int statusType, List<byte[]> attributes) {
        for (byte[] a : attributes) {
            if (a.length < 2 || (a[1] & 0xFF) != a.length) {
                throw new IllegalArgumentException("not one attribute: its length octet must equal its size");
            }
        }
        return new AccountingEvent(statusType, attributes, -1);
    }

    /** Accounting-On: the NAS started and has no sessions; {@code nasIdentifier} may be {@code null}. */
    public static AccountingEvent accountingOn(String nasIdentifier) {
        return nasWide(ACCOUNTING_ON, nasIdentifier);
    }

    /** Accounting-Off: the NAS stops and ends all its sessions; {@code nasIdentifier} may be {@code null}. */
    public static AccountingEvent accountingOff(String nasIdentifier) {
        return nasWide(ACCOUNTING_OFF, nasIdentifier);
    }

    private static AccountingEvent nasWide(int statusType, String nasIdentifier) {
        List<byte[]> attributes = new ArrayList<>();
        if (nasIdentifier != null) {
            attributes.add(attribute(32, nasIdentifier.getBytes(StandardCharsets.UTF_8)));
        }
        attributes.add(uint32(55, System.currentTimeMillis() / 1000));
        return of(statusType, attributes);
    }

    /** The NAS's retransmission of this event, sent {@code seconds} after it happened (Acct-Delay-Time). */
    public AccountingEvent delay(long seconds) {
        if (seconds < 0 || seconds > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException("Acct-Delay-Time is 0 to 2^32-1 seconds");
        }
        return new AccountingEvent(statusType, attributes, seconds);
    }

    /** This event with another attribute after the others. */
    public AccountingEvent with(int type, String value) {
        return with(attribute(type, value.getBytes(StandardCharsets.UTF_8)));
    }

    /** This event with another whole attribute (type, length, value) after the others. */
    public AccountingEvent with(byte[] attribute) {
        List<byte[]> more = new ArrayList<>(attributes);
        more.add(attribute.clone());
        return of(statusType, more).delayed(delaySeconds);
    }

    private AccountingEvent delayed(long seconds) {
        return seconds < 0 ? this : new AccountingEvent(statusType, attributes, seconds);
    }

    public int statusType() {
        return statusType;
    }

    /** The Accounting-Request with this identifier, signed with {@code secret}. */
    public byte[] build(int identifier, byte[] secret) {
        PacketBuilder request = PacketBuilder.accountingRequest(identifier).uint32(40, statusType);
        for (byte[] a : attributes) {
            request.raw(a);
        }
        if (delaySeconds >= 0) {
            request.uint32(41, delaySeconds);
        }
        return request.secret(secret).build();
    }

    static byte[] attribute(int type, byte[] value) {
        if (value.length > 253) {
            throw new IllegalArgumentException("attribute " + type + ": at most 253 bytes");
        }
        byte[] a = new byte[2 + value.length];
        a[0] = (byte) type;
        a[1] = (byte) a.length;
        System.arraycopy(value, 0, a, 2, value.length);
        return a;
    }

    static byte[] uint32(int type, long value) {
        return new byte[] {
            (byte) type, 6, (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
        };
    }

    static byte[] vendor(int vendorId, int vendorType, byte[] value) {
        byte[] inner = attribute(vendorType, value);
        byte[] v = new byte[4 + inner.length];
        v[0] = (byte) (vendorId >>> 24);
        v[1] = (byte) (vendorId >>> 16);
        v[2] = (byte) (vendorId >>> 8);
        v[3] = (byte) vendorId;
        System.arraycopy(inner, 0, v, 4, inner.length);
        return attribute(26, v);
    }
}
