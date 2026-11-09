/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.util.UUID;

/**
 * Asks a domain controller's endpoint mapper (TCP 135, C706 appendix L/O) on which TCP port an interface listens:
 * {@code ept_map} with a tower for {@code ncacn_ip_tcp}; the answer's tower carries the port.
 */
final class EndpointMapper {

    static final UUID EPM = UUID.fromString("e1af8308-5d1f-11c9-91a4-08002b14a0fa");
    private static final int EPT_MAP = 3;

    private EndpointMapper() {}

    /** The TCP port of {@code iface} {@code major.minor} on the server behind {@code mapper}. */
    static int port(InetSocketAddress mapper, UUID iface, int major, int minor, Duration timeout) throws IOException {
        try (RpcConnection rpc = new RpcConnection(mapper, timeout)) {
            rpc.bind(EPM, 3, 0, null);
            byte[] tower = tower(iface, major, minor);
            Ndr.Writer w = new Ndr.Writer();
            w.nullPointer(); // object uuid
            w.pointer(); // map_tower
            w.u32(tower.length).u32(tower.length).bytes(tower).align(4);
            w.bytes(new byte[20]); // entry handle
            w.u32(4); // max towers
            Ndr.Reader r = new Ndr.Reader(rpc.call(EPT_MAP, w.toByteArray()));
            r.skip(20); // entry handle
            long towers = r.u32();
            r.u32(); // max count
            r.u32(); // offset
            long actual = r.u32();
            long[] referents = new long[(int) actual];
            for (int i = 0; i < actual; i++) {
                referents[i] = r.u32();
            }
            for (int i = 0; i < actual && i < towers; i++) {
                if (referents[i] == 0) {
                    continue;
                }
                long length = r.u32();
                r.u32(); // max count
                int port = portOf(r.bytes((int) length));
                r.align(4);
                if (port > 0) {
                    return port;
                }
            }
            throw new IOException("endpoint mapper: interface " + iface + " not registered for ncacn_ip_tcp");
        }
    }

    /** A five-floor tower: interface, NDR, connection-oriented RPC, TCP port 0, IP 0.0.0.0. */
    static byte[] tower(UUID iface, int major, int minor) {
        ByteBuffer b = ByteBuffer.allocate(75).order(ByteOrder.LITTLE_ENDIAN);
        b.putShort((short) 5);
        floorUuid(b, iface, major, minor);
        floorUuid(b, RpcConnection.NDR, 2, 0);
        b.putShort((short) 1).put((byte) 0x0b).putShort((short) 2).putShort((short) 0);
        b.putShort((short) 1)
                .put((byte) 0x07)
                .putShort((short) 2)
                .order(ByteOrder.BIG_ENDIAN)
                .putShort((short) 0);
        b.order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 1)
                .put((byte) 0x09)
                .putShort((short) 4)
                .putInt(0);
        return java.util.Arrays.copyOf(b.array(), b.position());
    }

    private static void floorUuid(ByteBuffer b, UUID id, int major, int minor) {
        b.putShort((short) 19).put((byte) 0x0d).put(Ndr.uuidBytes(id)).putShort((short) major);
        b.putShort((short) 2).putShort((short) minor);
    }

    /** The TCP port floor (protocol 0x07, big-endian) of a tower, 0 if none. */
    static int portOf(byte[] tower) {
        ByteBuffer b = ByteBuffer.wrap(tower).order(ByteOrder.LITTLE_ENDIAN);
        int floors = b.getShort() & 0xFFFF;
        for (int f = 0; f < floors && b.remaining() >= 4; f++) {
            int lhsLength = b.getShort() & 0xFFFF;
            byte[] lhs = new byte[lhsLength];
            b.get(lhs);
            int rhsLength = b.getShort() & 0xFFFF;
            byte[] rhs = new byte[rhsLength];
            b.get(rhs);
            if (lhsLength == 1 && lhs[0] == 0x07 && rhsLength == 2) {
                return (rhs[0] & 0xFF) << 8 | (rhs[1] & 0xFF);
            }
        }
        return 0;
    }
}
