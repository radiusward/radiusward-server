/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * The few pieces of NDR (DCE/RPC's Network Data Representation, C706 chapter 14, little-endian) Netlogon needs:
 * primitives aligned to their size, unique pointers, conformant-varying strings, UUIDs.
 */
final class Ndr {

    private Ndr() {}

    /** Writes NDR into a growing buffer; alignment is relative to the start of the stub. */
    static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private int referent = 0x00020000;

        Writer align(int n) {
            while (out.size() % n != 0) {
                out.write(0);
            }
            return this;
        }

        Writer u8(int v) {
            out.write(v);
            return this;
        }

        Writer u16(int v) {
            align(2);
            out.write(v);
            out.write(v >>> 8);
            return this;
        }

        Writer u32(long v) {
            align(4);
            for (int i = 0; i < 4; i++) {
                out.write((int) (v >>> (8 * i)));
            }
            return this;
        }

        Writer u64(long v) {
            align(8);
            for (int i = 0; i < 8; i++) {
                out.write((int) (v >>> (8 * i)));
            }
            return this;
        }

        Writer bytes(byte[] b) {
            out.write(b, 0, b.length);
            return this;
        }

        /** A non-null unique pointer's referent id; the pointed-to data follows (deferred where the IDL says so). */
        Writer pointer() {
            return u32(referent += 4);
        }

        Writer nullPointer() {
            return u32(0);
        }

        /** {@code [string] wchar_t*}: max count, offset 0, actual count, UTF-16LE with the terminating 0. */
        Writer string(String s) {
            byte[] chars = (s + "\0").getBytes(StandardCharsets.UTF_16LE);
            int count = chars.length / 2;
            u32(count).u32(0).u32(count);
            return bytes(chars);
        }

        /** A unique pointer to a {@code [string] wchar_t*}, or null. */
        Writer uniqueString(String s) {
            if (s == null) {
                return nullPointer();
            }
            pointer();
            return string(s);
        }

        Writer uuid(UUID id) {
            bytes(uuidBytes(id));
            return this;
        }

        int size() {
            return out.size();
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }

    /** Reads NDR from a stub. */
    static final class Reader {
        private final ByteBuffer in;

        Reader(byte[] stub) {
            this.in = ByteBuffer.wrap(stub).order(ByteOrder.LITTLE_ENDIAN);
        }

        Reader align(int n) {
            while (in.position() % n != 0) {
                in.get();
            }
            return this;
        }

        int u8() {
            return in.get() & 0xFF;
        }

        int u16() {
            align(2);
            return in.getShort() & 0xFFFF;
        }

        long u32() {
            align(4);
            return in.getInt() & 0xFFFF_FFFFL;
        }

        long u64() {
            align(8);
            return in.getLong();
        }

        byte[] bytes(int n) {
            byte[] b = new byte[n];
            in.get(b);
            return b;
        }

        void skip(int n) {
            in.position(in.position() + n);
        }

        /** A 32-bit value at an absolute position, not moving the reader. */
        long u32At(int at) {
            return in.getInt(at) & 0xFFFF_FFFFL;
        }

        int remaining() {
            return in.remaining();
        }

        int position() {
            return in.position();
        }
    }

    /** A UUID as DCE/RPC sends it: the first three fields little-endian, the rest as is. */
    static byte[] uuidBytes(UUID id) {
        ByteBuffer b = ByteBuffer.allocate(16);
        long msb = id.getMostSignificantBits();
        b.order(ByteOrder.LITTLE_ENDIAN)
                .putInt((int) (msb >>> 32))
                .putShort((short) (msb >>> 16))
                .putShort((short) msb);
        b.order(ByteOrder.BIG_ENDIAN).putLong(id.getLeastSignificantBits());
        return b.array();
    }
}
