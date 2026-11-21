/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.client;

import io.radiusward.auth.Md4;
import io.radiusward.eap.EapPwdKeys;
import io.radiusward.eap.MsChap;
import io.radiusward.eap.P256;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * EAP-pwd (RFC 5931), group 19: the ID exchange as the server offers it, the Commit with the password element, and
 * the Confirm, the server's checked before the peer's goes out; the MSK as both sides derive it.
 */
final class PwdPeer {

    private static final int ID = 1;
    private static final int COMMIT = 2;
    private static final int CONFIRM = 3;
    private static final int PREP_MS = 1;

    private final EapLogin login;
    private byte[] serverId;
    private byte[] token;
    private byte[] preparedPassword;
    private BigInteger scalar;
    private P256.Point element;
    private BigInteger serverScalar;
    private P256.Point serverElement;
    private BigInteger k;

    PwdPeer(EapLogin login) {
        this.login = login;
    }

    boolean serverProved;
    byte[] msk;

    byte[] answer(byte[] request) {
        int exchange = request[0] & 0x3F;
        return switch (exchange) {
            case ID -> id(request);
            case COMMIT -> commit(request);
            case CONFIRM -> confirm(request);
            default -> throw new IllegalStateException("EAP-pwd: unknown exchange " + exchange);
        };
    }

    /** Group, random function, PRF, token and preparation as offered; then our identity. */
    private byte[] id(byte[] request) {
        int group = (request[1] & 0xFF) << 8 | (request[2] & 0xFF);
        if (group != 19) {
            throw new IllegalStateException("EAP-pwd: only group 19 is supported, the server offers " + group);
        }
        token = Arrays.copyOfRange(request, 5, 9);
        serverId = Arrays.copyOfRange(request, 10, request.length);
        preparedPassword = (request[9] & 0xFF) == PREP_MS
                ? Md4.digest(MsChap.ntHash(login.password))
                : login.password.getBytes(StandardCharsets.UTF_8);
        byte[] id = login.user.getBytes(StandardCharsets.UTF_8);
        byte[] d = new byte[1 + 9 + id.length];
        d[0] = ID;
        System.arraycopy(request, 1, d, 1, 9);
        System.arraycopy(id, 0, d, 10, id.length);
        return d;
    }

    private byte[] commit(byte[] request) {
        serverElement = P256.decode(request, 1);
        serverScalar = new BigInteger(1, Arrays.copyOfRange(request, 65, 97));
        P256.Point pwe = EapPwdKeys.passwordElement(
                preparedPassword, serverId, login.user.getBytes(StandardCharsets.UTF_8), token);
        if (pwe == null || !P256.onCurve(serverElement)) {
            throw new IllegalStateException("EAP-pwd: no password element, or the server's element is off the curve");
        }
        BigInteger mask = P256.randomScalar(EapBytes.RANDOM);
        BigInteger privateValue = P256.randomScalar(EapBytes.RANDOM);
        scalar = privateValue.add(mask).mod(P256.N);
        element = P256.negate(P256.multiply(pwe, mask));
        k = P256.multiply(P256.add(P256.multiply(pwe, serverScalar), serverElement), privateValue)
                .x();
        byte[] d = new byte[97];
        d[0] = COMMIT;
        System.arraycopy(element.encode(), 0, d, 1, 64);
        System.arraycopy(P256.bytes(scalar), 0, d, 65, 32);
        return d;
    }

    /** The server's Confirm proves it knew the password; only then our own goes out. */
    private byte[] confirm(byte[] request) {
        byte[] serverConfirm = Arrays.copyOfRange(request, 1, request.length);
        byte[] expected = EapPwdKeys.confirm(k, serverElement, serverScalar, element, scalar);
        serverProved = MessageDigest.isEqual(expected, serverConfirm);
        if (!serverProved) {
            throw new IllegalStateException("the server's EAP-pwd Confirm does not verify");
        }
        byte[] own = EapPwdKeys.confirm(k, element, scalar, serverElement, serverScalar);
        msk = EapPwdKeys.msk(k, own, serverConfirm, scalar, serverScalar);
        byte[] d = new byte[33];
        d[0] = CONFIRM;
        System.arraycopy(own, 0, d, 1, 32);
        return d;
    }
}
