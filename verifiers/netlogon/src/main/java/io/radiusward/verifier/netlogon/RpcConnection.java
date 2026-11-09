/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.util.UUID;

/**
 * A connection-oriented DCE/RPC client over TCP ({@code ncacn_ip_tcp}, C706 chapter 12, MS-RPCE): bind to one
 * interface with the NDR transfer syntax, then requests and responses, fragmented as negotiated. Authentication is
 * added by a {@link Security} (the Netlogon secure channel); without one, calls go in the clear. One call at a time;
 * not thread-safe.
 */
final class RpcConnection implements AutoCloseable {

    static final UUID NDR = UUID.fromString("8a885d04-1ceb-11c9-9fe8-08002b104860");

    static final int PTYPE_REQUEST = 0;
    static final int PTYPE_RESPONSE = 2;
    static final int PTYPE_FAULT = 3;
    static final int PTYPE_BIND = 11;
    static final int PTYPE_BIND_ACK = 12;
    static final int PTYPE_BIND_NAK = 13;
    static final int FIRST_FRAG = 0x01;
    static final int LAST_FRAG = 0x02;
    static final int HEADER = 16;
    private static final int MAX_FRAG = 4280;

    /** Authentication of the PDUs: what the bind carries, and how requests and responses are protected. */
    interface Security {
        int authType();

        int authLevel();

        /** The auth value of the bind (e.g. an NL_AUTH_MESSAGE negotiate). */
        byte[] bindToken();

        /** Checks the bind_ack's auth value. */
        void bindAccepted(byte[] token) throws IOException;

        /** Length of the auth value of a request. */
        int signatureLength();

        /**
         * Protects a request: may encrypt {@code stub} in place and returns the auth value.
         *
         * @param pdu the PDU up to and including the auth trailer header, signature still empty
         */
        byte[] protect(byte[] pdu, int stubOffset, int stubLength);

        /** Checks and decrypts a response's stub in place. */
        void unprotect(byte[] pdu, int stubOffset, int stubLength, byte[] authValue) throws IOException;
    }

    private final Socket socket;
    private final DataInputStream in;
    private final OutputStream out;
    private int callId;
    private int maxXmit = MAX_FRAG;
    private Security security;

    RpcConnection(InetSocketAddress address, Duration timeout) throws IOException {
        socket = new Socket();
        socket.connect(address, (int) timeout.toMillis());
        socket.setSoTimeout((int) timeout.toMillis());
        socket.setTcpNoDelay(true);
        in = new DataInputStream(socket.getInputStream());
        out = socket.getOutputStream();
    }

    /** Binds to {@code iface} {@code major.minor}; with {@code security}, every following call is protected by it. */
    void bind(UUID iface, int major, int minor, Security security) throws IOException {
        ByteBuffer body = ByteBuffer.allocate(72).order(ByteOrder.LITTLE_ENDIAN);
        body.putShort((short) MAX_FRAG).putShort((short) MAX_FRAG).putInt(0); // max xmit/recv, assoc group
        body.put((byte) 1).put((byte) 0).putShort((short) 0); // one context element
        body.putShort((short) 0).put((byte) 1).put((byte) 0); // context id 0, one transfer syntax
        body.put(Ndr.uuidBytes(iface)).putShort((short) major).putShort((short) minor);
        body.put(Ndr.uuidBytes(NDR)).putShort((short) 2).putShort((short) 0);
        byte[] auth = security == null ? null : security.bindToken();
        send(PTYPE_BIND, FIRST_FRAG | LAST_FRAG, ++callId, body.array(), 0, body.position(), security, auth);
        Pdu ack = receive();
        if (ack.type == PTYPE_BIND_NAK) {
            throw new IOException("bind refused (reason " + (ack.body.length >= 2 ? ack.u16(0) : -1) + ")");
        }
        if (ack.type != PTYPE_BIND_ACK) {
            throw new IOException("unexpected PDU type " + ack.type + " in answer to bind");
        }
        maxXmit = Math.min(MAX_FRAG, ack.u16(0));
        int secAddr = ack.u16(8);
        int at = 10 + secAddr;
        at = (at + 3) & ~3;
        int results = ack.body[at] & 0xFF;
        if (results < 1 || ack.u16(at + 4) != 0) {
            throw new IOException("bind: interface or transfer syntax not accepted (result "
                    + (results < 1 ? -1 : ack.u16(at + 4)) + ", reason " + (results < 1 ? -1 : ack.u16(at + 6)) + ")");
        }
        if (security != null) {
            if (ack.authValue == null) {
                throw new IOException("bind_ack without authentication");
            }
            security.bindAccepted(ack.authValue);
        }
        this.security = security;
    }

    /** One call: the request stub for {@code opnum}, the response stub. */
    byte[] call(int opnum, byte[] stub) throws IOException {
        int id = ++callId;
        int signature = security == null ? 0 : security.signatureLength();
        int chunk = maxXmit - HEADER - 8 - (security == null ? 0 : 8 + signature + 16);
        for (int off = 0; off == 0 || off < stub.length; off += chunk) {
            int len = Math.min(chunk, stub.length - off);
            int flags = (off == 0 ? FIRST_FRAG : 0) | (off + len >= stub.length ? LAST_FRAG : 0);
            ByteBuffer body = ByteBuffer.allocate(8 + len).order(ByteOrder.LITTLE_ENDIAN);
            body.putInt(stub.length).putShort((short) 0).putShort((short) opnum).put(stub, off, len);
            send(PTYPE_REQUEST, flags, id, body.array(), 8, len, security, null);
            if (stub.length == 0) {
                break;
            }
        }
        java.io.ByteArrayOutputStream result = new java.io.ByteArrayOutputStream();
        while (true) {
            Pdu pdu = receive();
            if (pdu.type == PTYPE_FAULT) {
                throw new RpcFault(pdu.body.length >= 12 ? pdu.u32(8) : -1);
            }
            if (pdu.type != PTYPE_RESPONSE || pdu.callId != id) {
                throw new IOException("unexpected PDU type " + pdu.type + " (call " + pdu.callId + ")");
            }
            if (security != null) {
                security.unprotect(pdu.raw, HEADER + 8, pdu.stubLength - 8, pdu.authValue);
            }
            result.write(pdu.raw, HEADER + 8, pdu.stubLength - 8);
            if ((pdu.flags & LAST_FRAG) != 0) {
                return result.toByteArray();
            }
        }
    }

    /** A fault PDU: the server could not run the call. */
    static final class RpcFault extends IOException {
        final long status;

        RpcFault(long status) {
            super(String.format("RPC fault 0x%08x", status));
            this.status = status;
        }
    }

    private void send(
            int type, int flags, int id, byte[] body, int stubOffset, int stubLength, Security sec, byte[] auth)
            throws IOException {
        boolean protectedRequest = sec != null && type == PTYPE_REQUEST;
        int bodyLength = type == PTYPE_REQUEST ? 8 + stubLength : body.length;
        int pad = (auth != null || protectedRequest) ? (4 - (bodyLength % 4)) % 4 : 0;
        int authLength = auth != null ? auth.length : protectedRequest ? sec.signatureLength() : 0;
        int frag = HEADER + bodyLength + (authLength > 0 ? pad + 8 + authLength : 0);
        ByteBuffer pdu = ByteBuffer.allocate(frag).order(ByteOrder.LITTLE_ENDIAN);
        pdu.put((byte) 5).put((byte) 0).put((byte) type).put((byte) flags);
        pdu.put((byte) 0x10).put((byte) 0).put((byte) 0).put((byte) 0); // little-endian, ASCII, IEEE
        pdu.putShort((short) frag).putShort((short) authLength).putInt(id);
        pdu.put(body, 0, bodyLength);
        if (authLength > 0) {
            pdu.put(new byte[pad]);
            int authType = auth != null ? sec.authType() : sec.authType();
            pdu.put((byte) authType)
                    .put((byte) sec.authLevel())
                    .put((byte) pad)
                    .put((byte) 0)
                    .putInt(0);
            if (auth != null) {
                pdu.put(auth);
            } else {
                byte[] raw = pdu.array();
                byte[] signature = sec.protect(raw, HEADER + 8, stubLength + pad);
                pdu.put(signature);
            }
        }
        out.write(pdu.array());
        out.flush();
    }

    private Pdu receive() throws IOException {
        byte[] header = new byte[HEADER];
        in.readFully(header);
        ByteBuffer h = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN);
        if (header[0] != 5 || (header[4] & 0xF0) != 0x10) {
            throw new IOException("not a little-endian DCE/RPC v5 PDU");
        }
        int frag = h.getShort(8) & 0xFFFF;
        int authLength = h.getShort(10) & 0xFFFF;
        if (frag < HEADER || frag > 65_535) {
            throw new IOException("bad fragment length " + frag);
        }
        byte[] raw = new byte[frag];
        System.arraycopy(header, 0, raw, 0, HEADER);
        in.readFully(raw, HEADER, frag - HEADER);
        Pdu pdu = new Pdu();
        pdu.raw = raw;
        pdu.type = header[2] & 0xFF;
        pdu.flags = header[3] & 0xFF;
        pdu.callId = h.getInt(12);
        int bodyEnd = frag;
        if (authLength > 0) {
            int trailer = frag - authLength - 8;
            int pad = raw[trailer + 2] & 0xFF;
            pdu.authValue = java.util.Arrays.copyOfRange(raw, trailer + 8, frag);
            bodyEnd = trailer - pad;
        }
        pdu.body = java.util.Arrays.copyOfRange(raw, HEADER, bodyEnd);
        pdu.stubLength = bodyEnd - HEADER;
        return pdu;
    }

    private static final class Pdu {
        byte[] raw;
        byte[] body;
        byte[] authValue;
        int type;
        int flags;
        int callId;
        int stubLength;

        int u16(int at) {
            return (body[at] & 0xFF) | (body[at + 1] & 0xFF) << 8;
        }

        long u32(int at) {
            return (u16(at) | (long) u16(at + 2) << 16) & 0xFFFF_FFFFL;
        }
    }

    @Override
    public void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}
