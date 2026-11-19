/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import io.radiusward.auth.AttributeItem;
import io.radiusward.auth.Md4;
import io.radiusward.eap.EapPacket;
import io.radiusward.eap.EapPwdKeys;
import io.radiusward.eap.MsChap;
import io.radiusward.eap.P256;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * EAP-pwd (RFC 5931; ADR 0042): mutual authentication with a password and no certificate, group 19 (P-256) with
 * HMAC-SHA256. The server's ID request offers the group, a token and the password preparation — none (the cleartext
 * password, for stores that allow cleartext) or MS (MD4 of the NT hash, for stores holding NT-Password); the peer's ID
 * response gives its identity. Both derive the password element from the token, both identities and the password
 * (hunting and pecking, always 40 rounds), exchange Commit (element and scalar) and Confirm messages, and the MSK and
 * EMSK follow from the shared secret. Hashes and the KDF follow RFC 5931 as wpa_supplicant and hostapd compute them.
 */
final class EapPwd implements EapMethod {

    static final int TYPE = EapPacket.TYPE_PWD;
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
        return Step.succeeded(EapPwdKeys.msk(k, d, confirmServer, peerScalar, scalar));
    }

    private Step message(int exchange, byte[] body) {
        byte[] m = new byte[1 + body.length];
        m[0] = (byte) exchange;
        System.arraycopy(body, 0, m, 1, body.length);
        return Step.next(m);
    }

    static P256.Point passwordElement(byte[] password, byte[] serverId, byte[] peerId, byte[] token) {
        return EapPwdKeys.passwordElement(password, serverId, peerId, token);
    }

    static byte[] h(byte[]... parts) {
        return EapPwdKeys.h(parts);
    }

    static byte[] kdf(byte[] key, byte[] label, int bits) {
        return EapPwdKeys.kdf(key, label, bits);
    }
}
