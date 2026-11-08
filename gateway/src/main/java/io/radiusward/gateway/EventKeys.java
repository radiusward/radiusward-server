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
 * The byte layout is part of the dedup contract; {@code EventKeysTest} pins it with fixed vectors.
 */
public final class EventKeys {

    private static final int MAX_SESSION_ID = 253;

    private final UnsafeBuffer scratch = new UnsafeBuffer(new byte[64 + MAX_SESSION_ID]);
    private final Murmur3 murmur = new Murmur3();

    private long sessionHi;
    private long sessionLo;
    private long exactHi;
    private long exactLo;

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
        int idLength = Math.min(sessionIdLength, MAX_SESSION_ID);

        scratch.putInt(0, nasId, LITTLE_ENDIAN);
        if (idLength > 0) {
            scratch.putBytes(4, sessionIdBuffer, sessionIdOffset, idLength);
        }
        murmur.hash(scratch, 0, 4 + idLength);
        sessionHi = murmur.hi();
        sessionLo = murmur.lo();

        scratch.putInt(0, nasId, LITTLE_ENDIAN);
        scratch.putInt(4, (int) statusType, LITTLE_ENDIAN);
        scratch.putLong(8, sessionTime, LITTLE_ENDIAN);
        scratch.putLong(16, eventTimestamp, LITTLE_ENDIAN);
        scratch.putLong(24, inputOctets, LITTLE_ENDIAN);
        scratch.putLong(32, outputOctets, LITTLE_ENDIAN);
        scratch.putByte(40, (byte) presence);
        if (idLength > 0) {
            scratch.putBytes(41, sessionIdBuffer, sessionIdOffset, idLength);
        }
        murmur.hash(scratch, 0, 41 + idLength);
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
}
