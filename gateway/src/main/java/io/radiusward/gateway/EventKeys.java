/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static java.nio.ByteOrder.LITTLE_ENDIAN;

import org.agrona.DirectBuffer;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * Computes the two keys of an accounting event (ADR 0003) without allocating:
 *
 * <ul>
 *   <li><b>session key</b> = Murmur3-128 of (nasId, Acct-Session-Id): identifies the session on every
 *       gateway;
 *   <li><b>exact key</b> = Murmur3-128 of (nasId, Acct-Status-Type, Acct-Session-Time, Event-Timestamp,
 *       64 bit octet counters, presence bits, Acct-Session-Id): identifies one event. It deliberately leaves
 *       out Acct-Delay-Time and the RADIUS Identifier, which change on retransmission.
 * </ul>
 *
 * When the NAS entry tells apart the devices behind it (ADR 0019), both keys also cover the device identity:
 * {@code nasId, length, identity} instead of {@code nasId} alone, so devices never share a session; without an
 * identity the bytes are exactly as before. The device <b>scope</b> — the {@code nasId} the cluster groups sessions by
 * for Accounting-On/Off — is the NAS id, or a 32-bit hash of NAS id and identity.
 *
 * The byte layout is part of the dedup contract; {@code EventKeysTest} pins it with fixed vectors.
 */
public final class EventKeys {

    private static final int MAX_SESSION_ID = 253;

    private final UnsafeBuffer scratch =
            new UnsafeBuffer(new byte[64 + 1 + DeviceIdentity.MAX_LENGTH + MAX_SESSION_ID]);
    private final Murmur3 murmur = new Murmur3();

    private long sessionHi;
    private long sessionLo;
    private long exactHi;
    private long exactLo;
    private int scope;

    /**
     * Computes both keys.
     *
     * @param presence bit 0: session time present, bit 1: event timestamp present
     */
    public void compute(
            int nasId,
            long statusType,
            int presence,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            DirectBuffer sessionIdBuffer,
            int sessionIdOffset,
            int sessionIdLength) {
        compute(
                nasId,
                null,
                0,
                statusType,
                presence,
                sessionTime,
                eventTimestamp,
                inputOctets,
                outputOctets,
                sessionIdBuffer,
                sessionIdOffset,
                sessionIdLength);
    }

    /**
     * Computes both keys and the device scope for a device behind a NAS entry.
     *
     * @param device normalised device identity ({@link DeviceIdentity}); {@code deviceLength} 0 for none
     */
    public void compute(
            int nasId,
            DirectBuffer device,
            int deviceLength,
            long statusType,
            int presence,
            long sessionTime,
            long eventTimestamp,
            long inputOctets,
            long outputOctets,
            DirectBuffer sessionIdBuffer,
            int sessionIdOffset,
            int sessionIdLength) {
        int idLength = Math.min(sessionIdLength, MAX_SESSION_ID);
        int deviceBytes = deviceLength > 0 ? 1 + Math.min(deviceLength, DeviceIdentity.MAX_LENGTH) : 0;

        scratch.putInt(0, nasId, LITTLE_ENDIAN);
        if (deviceBytes > 0) {
            scratch.putByte(4, (byte) (deviceBytes - 1));
            scratch.putBytes(5, device, 0, deviceBytes - 1);
            murmur.hash(scratch, 0, 4 + deviceBytes);
            long h = murmur.hi() ^ murmur.lo();
            scope = (int) (h ^ (h >>> 32));
        } else {
            scope = nasId;
        }
        if (idLength > 0) {
            scratch.putBytes(4 + deviceBytes, sessionIdBuffer, sessionIdOffset, idLength);
        }
        murmur.hash(scratch, 0, 4 + deviceBytes + idLength);
        sessionHi = murmur.hi();
        sessionLo = murmur.lo();

        scratch.putInt(0, nasId, LITTLE_ENDIAN);
        scratch.putInt(4, (int) statusType, LITTLE_ENDIAN);
        scratch.putLong(8, sessionTime, LITTLE_ENDIAN);
        scratch.putLong(16, eventTimestamp, LITTLE_ENDIAN);
        scratch.putLong(24, inputOctets, LITTLE_ENDIAN);
        scratch.putLong(32, outputOctets, LITTLE_ENDIAN);
        scratch.putByte(40, (byte) presence);
        if (deviceBytes > 0) {
            scratch.putByte(41, (byte) (deviceBytes - 1));
            scratch.putBytes(42, device, 0, deviceBytes - 1);
        }
        if (idLength > 0) {
            scratch.putBytes(41 + deviceBytes, sessionIdBuffer, sessionIdOffset, idLength);
        }
        murmur.hash(scratch, 0, 41 + deviceBytes + idLength);
        exactHi = murmur.hi();
        exactLo = murmur.lo();
    }

    public long sessionHi() {
        return sessionHi;
    }

    public long sessionLo() {
        return sessionLo;
    }

    public long exactHi() {
        return exactHi;
    }

    public long exactLo() {
        return exactLo;
    }

    /** The device scope: the NAS id, or a hash of NAS id and device identity (sent as the command's nasId). */
    public int scope() {
        return scope;
    }
}
