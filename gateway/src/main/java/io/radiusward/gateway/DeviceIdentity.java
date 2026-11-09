/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.radius.codec.attributes.AccountingFields;
import org.agrona.DirectBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * The device behind a NAS entry (ADR 0019): the first configured identity attribute present in the request,
 * normalised into a reusable buffer. Allocation-free.
 *
 * <ul>
 *   <li>{@code nas-identifier}: the bytes as sent; empty counts as missing (Open-Mesh sends an empty one)
 *   <li>{@code called-station-id}: the MAC as 12 lower-case hex digits ({@code AA-BB-CC-DD-EE-FF:Guest},
 *       {@code aa:bb:cc:dd:ee:ff}, {@code aabb.ccdd.eeff} are all {@code aabbccddeeff}); a value that is not a MAC
 *       is taken as sent
 *   <li>{@code nas-ip-address}: dotted decimal
 * </ul>
 *
 * <p>Every packet of a session must resolve to the same attribute, or the session splits: prefer attributes the
 * device sends in every accounting packet (RFC 2866 requires NAS-IP-Address or NAS-Identifier; Called-Station-Id is
 * often missing from Interim and Stop). {@link #fallback()} tells when a later attribute of the list was used.
 */
final class DeviceIdentity {

    static final int MAX_LENGTH = 253;

    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[MAX_LENGTH]);
    private boolean fallback;

    /** Writes the identity of the request's device into {@link #buffer()}; returns its length, 0 if none. */
    int resolve(NasClient nas, AccountingFields fields) {
        NasClient.Identity[] list = nas.identity();
        for (int index = 0; index < list.length; index++) {
            NasClient.Identity identity = list[index];
            int length = switch (identity) {
                case NAS_IDENTIFIER ->
                    fields.has(AccountingFields.NAS_IDENTIFIER)
                            ? copy(fields.buffer(), fields.nasIdentifierOffset(), fields.nasIdentifierLength())
                            : 0;
                case CALLED_STATION_ID -> {
                    if (!fields.has(AccountingFields.CALLED_STATION_ID)) {
                        yield 0;
                    }
                    int offset = fields.calledStationIdOffset();
                    int n = fields.calledStationIdLength();
                    int mac = mac(fields.buffer(), offset, n, buffer);
                    yield mac > 0 ? mac : copy(fields.buffer(), offset, n);
                }
                case NAS_IP_ADDRESS ->
                    fields.has(AccountingFields.NAS_IP_ADDRESS) ? ipv4(fields.nasIpAddress(), buffer) : 0;
            };
            if (length > 0) {
                fallback = index > 0;
                return length;
            }
        }
        fallback = false;
        return 0;
    }

    /** Whether the last {@link #resolve} used an attribute after the first of the list. */
    boolean fallback() {
        return fallback;
    }

    DirectBuffer buffer() {
        return buffer;
    }

    private int copy(DirectBuffer source, int offset, int length) {
        int n = Math.min(length, MAX_LENGTH);
        buffer.putBytes(0, source, offset, n);
        return n;
    }

    /**
     * Normalises a MAC address (12 hex digits, optionally separated by {@code -}, {@code :} or {@code .}, optionally
     * followed by {@code :SSID}) to 12 lower-case hex digits at the start of {@code out}.
     *
     * @return 12, or -1 if the value does not start with a MAC address
     */
    static int mac(DirectBuffer in, int offset, int length, MutableDirectBuffer out) {
        int digits = 0;
        int i = 0;
        for (; i < length && digits < 12; i++) {
            byte b = in.getByte(offset + i);
            int v = hex(b);
            if (v >= 0) {
                out.putByte(digits++, (byte) (v < 10 ? '0' + v : 'a' + v - 10));
            } else if (b != '-' && b != ':' && b != '.') {
                return -1;
            }
        }
        if (digits < 12 || (i < length && in.getByte(offset + i) != ':')) {
            return -1; // too short, or more than a MAC before the SSID separator
        }
        return 12;
    }

    private static int hex(byte b) {
        if (b >= '0' && b <= '9') {
            return b - '0';
        }
        if (b >= 'a' && b <= 'f') {
            return b - 'a' + 10;
        }
        if (b >= 'A' && b <= 'F') {
            return b - 'A' + 10;
        }
        return -1;
    }

    /** Dotted decimal of an IPv4 address (value of NAS-IP-Address) at the start of {@code out}; returns its length. */
    static int ipv4(long address, MutableDirectBuffer out) {
        int n = 0;
        for (int shift = 24; shift >= 0; shift -= 8) {
            int octet = (int) (address >>> shift) & 0xFF;
            if (octet >= 100) {
                out.putByte(n++, (byte) ('0' + octet / 100));
            }
            if (octet >= 10) {
                out.putByte(n++, (byte) ('0' + octet / 10 % 10));
            }
            out.putByte(n++, (byte) ('0' + octet % 10));
            if (shift > 0) {
                out.putByte(n++, (byte) '.');
            }
        }
        return n;
    }
}
