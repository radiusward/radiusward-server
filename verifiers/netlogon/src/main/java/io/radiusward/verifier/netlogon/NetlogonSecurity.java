/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The Netlogon security provider for DCE/RPC (MS-NRPC §3.3, auth type 68, privacy level): every request is signed and
 * encrypted with the secure channel's AES session key, every response checked and decrypted (§3.3.4.2). Domain
 * controllers require it since the CVE-2020-1472 hardening.
 *
 * <p>The AES signature is 56 bytes, laid out as Windows actually sends it: algorithms, encrypted sequence number, the
 * first 8 bytes of the HMAC-SHA256 checksum, the encrypted confounder, then 24 zero bytes — not the 32-byte checksum
 * field the {@code NL_AUTH_SHA2_SIGNATURE} structure suggests.
 */
final class NetlogonSecurity implements RpcConnection.Security {

    static final int AUTH_TYPE = 68;
    static final int AUTH_LEVEL_PRIVACY = 6;
    static final int SIGNATURE_LENGTH = 56;
    private static final int HMAC_SHA256 = 0x0013;
    private static final int AES_128 = 0x001A;

    private final byte[] sessionKey;
    private final byte[] sealKey;
    private final String domain;
    private final String computer;
    private final SecureRandom random = new SecureRandom();
    /** One counter for both directions: every message, sent or received, takes the next number. */
    private long sequenceNumber;

    NetlogonSecurity(byte[] sessionKey, String domain, String computer) {
        this.sessionKey = sessionKey.clone();
        this.sealKey = new byte[16];
        for (int i = 0; i < 16; i++) {
            sealKey[i] = (byte) (sessionKey[i] ^ 0xF0);
        }
        this.domain = domain;
        this.computer = computer;
    }

    @Override
    public int authType() {
        return AUTH_TYPE;
    }

    @Override
    public int authLevel() {
        return AUTH_LEVEL_PRIVACY;
    }

    /** NL_AUTH_MESSAGE negotiate: NetBIOS domain and computer name as OEM strings. */
    @Override
    public byte[] bindToken() {
        byte[] d = (domain + "\0").getBytes(StandardCharsets.US_ASCII);
        byte[] c = (computer + "\0").getBytes(StandardCharsets.US_ASCII);
        ByteBuffer b = ByteBuffer.allocate(8 + d.length + c.length).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0).putInt(0x3).put(d).put(c);
        return b.array();
    }

    @Override
    public void bindAccepted(byte[] token) throws IOException {
        if (token.length < 8
                || ByteBuffer.wrap(token).order(ByteOrder.LITTLE_ENDIAN).getInt(0) != 1) {
            throw new IOException("the domain controller did not accept the Netlogon secure channel bind");
        }
    }

    @Override
    public int signatureLength() {
        return SIGNATURE_LENGTH;
    }

    @Override
    public byte[] protect(byte[] pdu, int offset, int length) {
        byte[] sequence = sequence(sequenceNumber++, true);
        byte[] confounder = new byte[8];
        random.nextBytes(confounder);
        byte[] head = head();
        byte[] checksum = Arrays.copyOf(checksum(head, confounder, pdu, offset, length), 8);
        Cipher seal = cipher(sealKey, iv(sequence), true);
        byte[] sealedConfounder = seal.update(confounder);
        byte[] sealed = seal.update(pdu, offset, length);
        System.arraycopy(sealed, 0, pdu, offset, length);
        byte[] encryptedSequence = cipher(sessionKey, iv(checksum), true).update(sequence);
        ByteBuffer signature = ByteBuffer.allocate(SIGNATURE_LENGTH);
        signature.put(head).put(encryptedSequence).put(checksum).put(sealedConfounder); // then 24 zero bytes
        return signature.array();
    }

    @Override
    public void unprotect(byte[] pdu, int offset, int length, byte[] signature) throws IOException {
        if (signature == null || signature.length < SIGNATURE_LENGTH) {
            throw new IOException("response without a Netlogon signature");
        }
        ByteBuffer s = ByteBuffer.wrap(signature).order(ByteOrder.LITTLE_ENDIAN);
        if ((s.getShort(0) & 0xFFFF) != HMAC_SHA256 || (s.getShort(2) & 0xFFFF) != AES_128) {
            throw new IOException("response signature is not AES / HMAC-SHA256");
        }
        byte[] checksum = Arrays.copyOfRange(signature, 16, 24);
        byte[] sequence = cipher(sessionKey, iv(checksum), false).update(Arrays.copyOfRange(signature, 8, 16));
        if (!MessageDigest.isEqual(sequence, sequence(sequenceNumber, false))) {
            throw new IOException("response sequence number out of order");
        }
        sequenceNumber++;
        Cipher open = cipher(sealKey, iv(sequence), false);
        byte[] confounder = open.update(Arrays.copyOfRange(signature, 24, 32));
        byte[] plain = open.update(pdu, offset, length);
        System.arraycopy(plain, 0, pdu, offset, length);
        byte[] expected = Arrays.copyOf(checksum(Arrays.copyOf(signature, 8), confounder, pdu, offset, length), 8);
        if (!MessageDigest.isEqual(expected, checksum)) {
            throw new IOException("response checksum does not match");
        }
    }

    /** SignatureAlgorithm, SealAlgorithm, Pad, Flags. */
    private static byte[] head() {
        return ByteBuffer.allocate(8)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) HMAC_SHA256)
                .putShort((short) AES_128)
                .putShort((short) 0xFFFF)
                .putShort((short) 0)
                .array();
    }

    /** The low 32 bits, then the high 32 bits, both big-endian; the client sets the top bit of the high half. */
    static byte[] sequence(long number, boolean client) {
        long high = (number >>> 32) & 0x7FFF_FFFFL;
        if (client) {
            high |= 0x8000_0000L;
        }
        return ByteBuffer.allocate(8).putInt((int) number).putInt((int) high).array();
    }

    private byte[] checksum(byte[] head, byte[] confounder, byte[] data, int offset, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sessionKey, "HmacSHA256"));
            mac.update(head);
            mac.update(confounder);
            mac.update(data, offset, length);
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] iv(byte[] eight) {
        byte[] iv = new byte[16];
        System.arraycopy(eight, 0, iv, 0, 8);
        System.arraycopy(eight, 0, iv, 8, 8);
        return iv;
    }

    private static Cipher cipher(byte[] key, byte[] iv, boolean encrypt) {
        try {
            Cipher c = Cipher.getInstance("AES/CFB8/NoPadding");
            c.init(
                    encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new IvParameterSpec(iv));
            return c;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
