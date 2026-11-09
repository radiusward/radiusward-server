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
import java.util.Arrays;
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

    static final int OP_SAM_LOGON_EX = 39;
    static final int NETWORK_INFORMATION = 2;
    static final int VALIDATION_SAM_INFO = 2;

    /** MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT | MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT | MSV1_0_ALLOW_MSVCHAPV2. */
    static final long PARAMETER_CONTROL = 0x20L | 0x800L | 0x0001_0000L;

    private final InetSocketAddress address;
    private final java.time.Duration timeout;
    private final RpcConnection rpc;
    private RpcConnection secure;
    private String computer;
    private final SecureRandom random = new SecureRandom();
    private byte[] sessionKey;
    private long negotiated;

    NetlogonClient(InetSocketAddress netlogon, Duration timeout) throws IOException {
        this.address = netlogon;
        this.timeout = timeout;
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
        this.computer = computer;
    }

    /** The result of a network logon. */
    record Logon(long status, byte[] userSessionKey) {}

    /**
     * A network logon ({@code NetrLogonSamLogonEx}, §3.5.4.5.1) over a sealed connection: the domain controller checks
     * the 24-byte NT response to the 8-byte challenge (for MS-CHAPv2 the challenge hash) and returns the user session
     * key (MD4 of the user's NT hash) when it is right.
     *
     * @param domain the user's NetBIOS domain
     */
    Logon samLogon(String server, String domain, String user, byte[] challenge, byte[] ntResponse) throws IOException {
        if (secure == null) {
            RpcConnection connection = new RpcConnection(address, timeout);
            try {
                connection.bind(NETLOGON, 1, 0, new NetlogonSecurity(sessionKey, domain, computer));
            } catch (IOException e) {
                connection.close();
                throw e;
            }
            secure = connection;
        }
        Ndr.Writer w = new Ndr.Writer()
                .uniqueString("\\\\" + server)
                .uniqueString(computer)
                .u16(NETWORK_INFORMATION)
                .u16(NETWORK_INFORMATION) // union discriminant
                .pointer(); // NETLOGON_NETWORK_INFO
        // NETLOGON_LOGON_IDENTITY_INFO: domain, parameter control, reserved, user, workstation
        unicodeString(w, domain);
        w.u32(PARAMETER_CONTROL).u32(0).u32(0);
        unicodeString(w, user);
        unicodeString(w, "");
        w.bytes(challenge);
        w.u16(ntResponse.length).u16(ntResponse.length).pointer(); // NtChallengeResponse
        w.u16(0).u16(0).nullPointer(); // LmChallengeResponse
        // deferred buffers, in order
        unicodeBuffer(w, domain);
        unicodeBuffer(w, user);
        w.u32(ntResponse.length).u32(0).u32(ntResponse.length).bytes(ntResponse);
        w.u16(VALIDATION_SAM_INFO);
        w.align(4).u32(0); // ExtraFlags
        byte[] stub = secure.call(OP_SAM_LOGON_EX, w.toByteArray());

        Ndr.Reader r = new Ndr.Reader(stub);
        long status = r.u32At(stub.length - 4);
        if (status != 0) {
            return new Logon(status, null);
        }
        // ValidationInformation: discriminant, pointer, then NETLOGON_VALIDATION_SAM_INFO whose UserSessionKey sits
        // after six times, six strings and seven 32-bit fields (120 bytes); the domain controller encrypts it with the
        // secure channel's session key (AES-CFB8, zero IV), also inside the sealed call
        byte[] encrypted = Arrays.copyOfRange(stub, 8 + 120, 8 + 136);
        return new Logon(0, NetlogonCrypto.aesCfb8(sessionKey, new byte[16], encrypted, false));
    }

    /** RPC_UNICODE_STRING inline part: length and maximum in bytes, a pointer to the characters (none if empty). */
    private static void unicodeString(Ndr.Writer w, String s) {
        int bytes = s.length() * 2;
        w.u16(bytes).u16(bytes);
        if (s.isEmpty()) {
            w.nullPointer();
        } else {
            w.pointer();
        }
    }

    private static void unicodeBuffer(Ndr.Writer w, String s) {
        if (!s.isEmpty()) {
            byte[] chars = s.getBytes(java.nio.charset.StandardCharsets.UTF_16LE);
            w.u32(s.length()).u32(0).u32(s.length()).bytes(chars);
        }
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
        if (secure != null) {
            secure.close();
        }
    }
}
