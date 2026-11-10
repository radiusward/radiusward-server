/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * EAP-pwd (RFC 5931; ADR 0042): mutual authentication with a password and no certificate, group 19 (P-256) with
 * HMAC-SHA256. The server's ID request offers the group, a token and the password preparation — none (the cleartext
 * password, for stores that allow cleartext) or MS (MD4 of the NT hash, for stores holding NT-Password); the peer's ID
 * response gives its identity. Both derive the password element from the token, both identities and the password
 * (hunting and pecking, always 40 rounds), exchange Commit (element and scalar) and Confirm messages, and the MSK and
 * EMSK follow from the shared secret. Hashes and the KDF follow RFC 5931 as wpa_supplicant and hostapd compute them.
 */
final class EapPwd implements EapMethod {

    static final int TYPE = 52;
    static final int GROUP = 19;
    private static final int RAND_FUNC = 1;
    private static final int PRF = 1;
    private static final int PREP_NONE = 0;
    private static final int PREP_MS = 1;
    private static final int ID = 1;
    private static final int COMMIT = 2;
    private static final int CONFIRM = 3;
    private static final int FLAG_LENGTH = 0x80;
    private static final int FLAG_MORE = 0x40;
    private static final byte[] CIPHERSUITE = {0, (byte) GROUP, RAND_FUNC, PRF};
    private static final SecureRandom RANDOM = new SecureRandom();

    private enum State {
        ID,
        COMMIT,
        CONFIRM
    }

    private final byte[] serverId;
    private State state = State.ID;
    private final byte[] token = new byte[4];
    private int prep;
    private byte[] password;
    private P256.Point pwe;
    private BigInteger privateValue;
    private BigInteger scalar;
    private P256.Point element;
    private BigInteger peerScalar;
    private P256.Point peerElement;
    private BigInteger k;
    private byte[] confirmServer;
    private final ByteArrayOutputStream fragments = new ByteArrayOutputStream();

    /** @param serverId the server's identity in the ID exchange ({@code auth.eap.pwd.server.id}) */
    EapPwd(byte[] serverId) {
        this.serverId = serverId.clone();
    }

    @Override
    public int type() {
        return TYPE;
    }

    /** The ID request: group, random function, PRF, token, preparation, server identity (§3.2.1). */
    @Override
    public Step start(int identifier, Credentials credentials) {
        password = secret(credentials);
        if (password == null) {
            return Step.FAILED;
        }
        RANDOM.nextBytes(token);
        byte[] body = new byte[2 + 1 + 1 + 4 + 1 + serverId.length];
        body[1] = (byte) GROUP;
        body[2] = RAND_FUNC;
        body[3] = PRF;
        System.arraycopy(token, 0, body, 4, 4);
        body[8] = (byte) prep;
        System.arraycopy(serverId, 0, body, 9, serverId.length);
        return message(ID, body);
    }

    /** The cleartext (prep none, stores allowing cleartext) or MD4 of the NT hash (prep MS); {@code null} without. */
    private byte[] secret(Credentials credentials) {
        for (AttributeItem p : credentials.passwords()) {
            if (p.attribute().equalsIgnoreCase(PasswordCheck.CLEARTEXT) && credentials.cleartextAllowed()) {
                prep = PREP_NONE;
                return p.value().getBytes(StandardCharsets.UTF_8);
            }
        }
        for (AttributeItem p : credentials.passwords()) {
            if (p.attribute().equalsIgnoreCase("NT-Password")) {
                byte[] ntHash = MsChap.parseNtPassword(p.value());
                if (ntHash != null) {
                    prep = PREP_MS;
                    return Md4.digest(ntHash);
                }
            }
        }
        return null;
    }

    @Override
    public Step process(int identifier, byte[] data, Credentials credentials) {
        if (data.length < 1) {
            return Step.FAILED;
        }
        int flags = data[0] & 0xFF;
        int exchange = flags & 0x3F;
        int offset = (flags & FLAG_LENGTH) != 0 ? 3 : 1; // a 2-byte total length with the first fragment
        if (data.length < offset || exchange != expected()) {
            return Step.FAILED;
        }
        if (fragments.size() + data.length - offset > 4096) {
            return Step.FAILED;
        }
        fragments.write(data, offset, data.length - offset);
        if ((flags & FLAG_MORE) != 0) {
            return Step.next(new byte[] {(byte) exchange}); // acknowledge the fragment (§3.3)
        }
        byte[] payload = fragments.toByteArray();
        fragments.reset();
        return switch (state) {
            case ID -> idResponse(payload);
            case COMMIT -> commitResponse(payload);
            case CONFIRM -> confirmResponse(payload);
        };
    }

    private int expected() {
        return switch (state) {
            case ID -> ID;
            case COMMIT -> COMMIT;
            case CONFIRM -> CONFIRM;
        };
    }

    /** The peer's ID response repeats our choices and the token, then names the peer; we answer with our Commit. */
    private Step idResponse(byte[] d) {
        if (d.length < 9
                || ((d[0] & 0xFF) << 8 | (d[1] & 0xFF)) != GROUP
                || d[2] != RAND_FUNC
                || d[3] != PRF
                || !MessageDigest.isEqual(Arrays.copyOfRange(d, 4, 8), token)
                || (d[8] & 0xFF) != prep) {
            return Step.FAILED;
        }
        byte[] peerId = Arrays.copyOfRange(d, 9, d.length);
        pwe = passwordElement(password, serverId, peerId, token);
        Arrays.fill(password, (byte) 0);
        if (pwe == null) {
            return Step.FAILED;
        }
        BigInteger mask;
        do {
            privateValue = P256.randomScalar(RANDOM);
            mask = P256.randomScalar(RANDOM);
            scalar = privateValue.add(mask).mod(P256.N);
        } while (scalar.compareTo(BigInteger.ONE) <= 0);
        element = P256.negate(P256.multiply(pwe, mask));
        state = State.COMMIT;
        byte[] body = new byte[3 * P256.FIELD_BYTES];
        System.arraycopy(element.encode(), 0, body, 0, 2 * P256.FIELD_BYTES);
        System.arraycopy(P256.bytes(scalar), 0, body, 2 * P256.FIELD_BYTES, P256.FIELD_BYTES);
        return message(COMMIT, body);
    }

    /** The peer's element and scalar, checked; the shared secret k; our Confirm. */
    private Step commitResponse(byte[] d) {
        if (d.length != 3 * P256.FIELD_BYTES) {
            return Step.FAILED;
        }
        peerElement = P256.decode(d, 0);
        peerScalar = new BigInteger(1, Arrays.copyOfRange(d, 2 * P256.FIELD_BYTES, 3 * P256.FIELD_BYTES));
        if (peerElement == null
                || peerScalar.compareTo(BigInteger.ONE) <= 0
                || peerScalar.compareTo(P256.N) >= 0
                || (peerScalar.equals(scalar) && peerElement.equals(element))) { // a reflection of ours
            return Step.FAILED;
        }
        P256.Point shared = P256.multiply(P256.add(P256.multiply(pwe, peerScalar), peerElement), privateValue);
        if (shared == null) {
            return Step.FAILED;
        }
        k = shared.x();
        confirmServer = h(
                P256.bytes(k),
                element.encode(),
                P256.bytes(scalar),
                peerElement.encode(),
                P256.bytes(peerScalar),
                CIPHERSUITE);
        state = State.CONFIRM;
        return message(CONFIRM, confirmServer);
    }

    /** The peer's Confirm over its own commit first; then the keys (§2.9). */
    private Step confirmResponse(byte[] d) {
        byte[] expected = h(
                P256.bytes(k),
                peerElement.encode(),
                P256.bytes(peerScalar),
                element.encode(),
                P256.bytes(scalar),
                CIPHERSUITE);
        if (d.length != 32 || !MessageDigest.isEqual(expected, d)) {
            return Step.FAILED;
        }
        byte[] sessionId = new byte[33];
        sessionId[0] = (byte) TYPE;
        System.arraycopy(h(CIPHERSUITE, P256.bytes(peerScalar), P256.bytes(scalar)), 0, sessionId, 1, 32);
        byte[] mk = h(P256.bytes(k), d, confirmServer);
        byte[] keys = kdf(mk, sessionId, 128 * 8);
        return Step.succeeded(Arrays.copyOf(keys, 64));
    }

    private Step message(int exchange, byte[] body) {
        byte[] m = new byte[1 + body.length];
        m[0] = (byte) exchange;
        System.arraycopy(body, 0, m, 1, body.length);
        return Step.next(m);
    }

    /**
     * The password element (§2.8.4.1, hunting and pecking): pwd-seed = H(token | peer-id | server-id | password |
     * counter); pwd-value = KDF(pwd-seed, "EAP-pwd Hunting And Pecking", 256); the first value below p whose y² is a
     * quadratic residue gives x, and y has the parity of pwd-seed's last bit. All 40 rounds always run.
     */
    static P256.Point passwordElement(byte[] password, byte[] serverId, byte[] peerId, byte[] token) {
        BigInteger x = null;
        boolean odd = false;
        for (int counter = 1; counter <= 40; counter++) {
            byte[] seed = h(token, peerId, serverId, password, new byte[] {(byte) counter});
            BigInteger value = new BigInteger(
                    1, kdf(seed, "EAP-pwd Hunting And Pecking".getBytes(StandardCharsets.US_ASCII), 256));
            boolean residue = value.compareTo(P256.P) < 0 && P256.isQuadraticResidue(P256.ySquared(value.mod(P256.P)));
            if (residue && x == null) {
                x = value;
                odd = (seed[31] & 1) == 1;
            }
        }
        if (x == null) {
            return null;
        }
        BigInteger y = P256.sqrt(P256.ySquared(x));
        if (y.testBit(0) != odd) {
            y = P256.P.subtract(y);
        }
        P256.Point point = new P256.Point(x, y);
        return P256.onCurve(point) ? point : null;
    }

    /** H: HMAC-SHA256 with a zero key over the parts (§2.4). */
    static byte[] h(byte[]... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
            for (byte[] part : parts) {
                mac.update(part);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The KDF (§2.5): K(i) = HMAC-SHA256(key, K(i-1) | i | label | L), i and L 16-bit, L the length in bits; the
     * result truncated to L bits.
     */
    static byte[] kdf(byte[] key, byte[] label, int bits) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            int bytes = (bits + 7) / 8;
            byte[] out = new byte[bytes];
            byte[] previous = new byte[0];
            for (int i = 1, at = 0; at < bytes; i++) {
                mac.update(previous);
                mac.update(new byte[] {(byte) (i >>> 8), (byte) i});
                mac.update(label);
                mac.update(new byte[] {(byte) (bits >>> 8), (byte) bits});
                previous = mac.doFinal();
                int n = Math.min(previous.length, bytes - at);
                System.arraycopy(previous, 0, out, at, n);
                at += n;
            }
            if (bits % 8 != 0) {
                out[bytes - 1] &= (byte) (0xFF << (8 - bits % 8));
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
