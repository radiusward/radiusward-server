/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.UUID;

/**
 * A Netlogon (MS-NRPC) client for one domain controller, as a workstation trust account: establishes the secure
 * channel (§3.1.4.1: NetrServerReqChallenge, NetrServerAuthenticate3 with AES) and keeps its session key.
 */
final class NetlogonClient implements AutoCloseable {

    static final UUID NETLOGON = UUID.fromString("12345678-1234-abcd-ef00-01234567cffb");
    static final int OP_REQ_CHALLENGE = 4;
    static final int OP_AUTHENTICATE3 = 26;
    static final int WORKSTATION_SECURE_CHANNEL = 2;

    /** Negotiated: AES (W), secure RPC (Y), strong keys and the usual capabilities, as Windows clients ask. */
    static final long NEGOTIATE_FLAGS = 0x612fffffL;

    static final long NEG_AES = 0x01000000L;
    static final long NEG_SECURE_RPC = 0x40000000L;

    private final RpcConnection rpc;

    private final SecureRandom random = new SecureRandom();
    private byte[] sessionKey;
    private long negotiated;

    NetlogonClient(InetSocketAddress netlogon, Duration timeout) throws IOException {
        this.rpc = new RpcConnection(netlogon, timeout);
        rpc.bind(NETLOGON, 1, 0, null);
    }

    /**
     * Authenticates the machine account (e.g. {@code RADIUSWARD$}, computer {@code RADIUSWARD}) with its NT hash.
     *
     * @throws NetlogonException with the NTSTATUS when the domain controller refuses
     */
    void authenticate(String server, String account, String computer, byte[] machineNtHash) throws IOException {
        byte[] clientChallenge = new byte[8];
        random.nextBytes(clientChallenge);
        Ndr.Writer w =
                new Ndr.Writer().uniqueString("\\\\" + server).string(computer).bytes(clientChallenge);
        Ndr.Reader r = new Ndr.Reader(rpc.call(OP_REQ_CHALLENGE, w.toByteArray()));
        byte[] serverChallenge = r.bytes(8);
        NetlogonException.check(r.u32(), "NetrServerReqChallenge");

        byte[] key = NetlogonCrypto.sessionKey(machineNtHash, clientChallenge, serverChallenge);
        byte[] clientCredential = NetlogonCrypto.credential(clientChallenge, key);
        w = new Ndr.Writer()
                .uniqueString("\\\\" + server)
                .string(account)
                .u16(WORKSTATION_SECURE_CHANNEL)
                .string(computer)
                .bytes(clientCredential)
                .u32(NEGOTIATE_FLAGS);
        r = new Ndr.Reader(rpc.call(OP_AUTHENTICATE3, w.toByteArray()));
        byte[] serverCredential = r.bytes(8);
        long flags = r.u32();
        r.u32(); // account RID
        NetlogonException.check(r.u32(), "NetrServerAuthenticate3");
        if (!MessageDigest.isEqual(serverCredential, NetlogonCrypto.credential(serverChallenge, key))) {
            throw new IOException("the domain controller's credential does not match: not the expected server");
        }
        if ((flags & NEG_AES) == 0 || (flags & NEG_SECURE_RPC) == 0) {
            throw new IOException(
                    String.format("the domain controller did not agree to AES and secure RPC (0x%08x)", flags));
        }
        this.sessionKey = key;
        this.negotiated = flags;
    }

    byte[] sessionKey() {
        return sessionKey.clone();
    }

    long negotiated() {
        return negotiated;
    }

    @Override
    public void close() {
        rpc.close();
    }
}
