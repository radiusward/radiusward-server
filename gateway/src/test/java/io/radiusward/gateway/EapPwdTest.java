/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.auth.AttributeItem;
import io.radiusward.gateway.EapMethod.Credentials;
import io.radiusward.gateway.EapMethod.Step;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * EAP-pwd (ADR 0042) against a peer written from RFC 5931 in this test: success with the cleartext and with an NT hash,
 * wrong passwords, a reflected commit, scalars and elements out of range, a wrong token, fragments; and P-256.
 */
class EapPwdTest {

    static final byte[] SERVER_ID = "radiusward".getBytes(StandardCharsets.US_ASCII);
    static final SecureRandom RANDOM = new SecureRandom();

    /** The peer side of RFC 5931, enough to drive the server. */
    static final class Peer {
        final byte[] id;
        final byte[] password; // as prepared: cleartext, or MD4 of the NT hash
        byte[] token;
        P256.Point pwe;
        BigInteger privateValue;
        BigInteger scalar;
        P256.Point element;
        BigInteger serverScalar;
        P256.Point serverElement;
        BigInteger k;

        Peer(String id, byte[] password) {
            this.id = id.getBytes(StandardCharsets.UTF_8);
            this.password = password;
        }

        byte[] idResponse(byte[] request) {
            token = Arrays.copyOfRange(request, 5, 9);
            byte[] d = new byte[1 + 9 + id.length];
            d[0] = 1;
            System.arraycopy(request, 1, d, 1, 9); // group, functions, token, preparation as offered
            System.arraycopy(id, 0, d, 10, id.length);
            return d;
        }

        byte[] commit(byte[] request) {
            serverElement = P256.decode(request, 1);
            serverScalar = new BigInteger(1, Arrays.copyOfRange(request, 65, 97));
            pwe = EapPwd.passwordElement(password, SERVER_ID, id, token);
            BigInteger mask = P256.randomScalar(RANDOM);
            privateValue = P256.randomScalar(RANDOM);
            scalar = privateValue.add(mask).mod(P256.N);
            element = P256.negate(P256.multiply(pwe, mask));
            k = P256.multiply(P256.add(P256.multiply(pwe, serverScalar), serverElement), privateValue)
                    .x();
            byte[] d = new byte[97];
            d[0] = 2;
            System.arraycopy(element.encode(), 0, d, 1, 64);
            System.arraycopy(P256.bytes(scalar), 0, d, 65, 32);
            return d;
        }

        byte[] confirm() {
            byte[] c = EapPwd.h(
                    P256.bytes(k),
                    element.encode(),
                    P256.bytes(scalar),
                    serverElement.encode(),
                    P256.bytes(serverScalar),
                    new byte[] {0, 19, 1, 1});
            byte[] d = new byte[33];
            d[0] = 3;
            System.arraycopy(c, 0, d, 1, 32);
            return d;
        }
    }

    static Credentials cleartext(String password, boolean allowed) {
        return new Credentials(List.of(new AttributeItem("Cleartext-Password", ":=", password)), allowed);
    }

    static Credentials ntHash(String password) {
        return new Credentials(
                List.of(new AttributeItem(
                        "NT-Password", ":=", java.util.HexFormat.of().formatHex(MsChap.ntHash(password)))),
                false);
    }

    private static Step run(EapPwd server, Credentials credentials, Peer peer) {
        Step id = server.start(1, credentials);
        Step commit = server.process(1, peer.idResponse(id.request()), credentials);
        if (commit.done()) {
            return commit;
        }
        Step confirm = server.process(2, peer.commit(commit.request()), credentials);
        if (confirm.done()) {
            return confirm;
        }
        return server.process(3, peer.confirm(), credentials);
    }

    @Test
    void cleartextAndNtHashPasswords() {
        Step ok = run(new EapPwd(SERVER_ID), cleartext("pw-1", true), new Peer("alice", "pw-1".getBytes()));
        assertThat(ok.success()).isTrue();
        assertThat(ok.msk()).hasSize(64);
        assertThat(run(new EapPwd(SERVER_ID), cleartext("pw-1", true), new Peer("alice", "pw-2".getBytes()))
                        .success())
                .isFalse();
        assertThat(run(new EapPwd(SERVER_ID), ntHash("pw-1"), new Peer("bob", Md4.digest(MsChap.ntHash("pw-1"))))
                        .success())
                .as("preparation MS: MD4 of the NT hash")
                .isTrue();
        assertThat(new EapPwd(SERVER_ID).start(1, cleartext("pw-1", false)))
                .as("cleartext of a store that does not allow it, and no NT hash")
                .isEqualTo(Step.FAILED);
    }

    @Test
    void theIdRequestOffersGroup19AndThePreparation() {
        byte[] request = new EapPwd(SERVER_ID).start(1, ntHash("pw")).request();
        assertThat(request[0]).as("ID exchange").isEqualTo((byte) 1);
        assertThat(Arrays.copyOfRange(request, 1, 5)).containsExactly(0, 19, 1, 1);
        assertThat(request[9]).as("preparation MS").isEqualTo((byte) 1);
        assertThat(Arrays.copyOfRange(request, 10, request.length)).isEqualTo(SERVER_ID);
    }

    @Test
    void reflectedOrInvalidCommitsAndWrongTokensFail() {
        Credentials c = cleartext("pw", true);
        EapPwd server = new EapPwd(SERVER_ID);
        Peer peer = new Peer("alice", "pw".getBytes());
        Step commit = server.process(1, peer.idResponse(server.start(1, c).request()), c);
        byte[] reflected = commit.request().clone();
        assertThat(server.process(2, reflected, c))
                .as("our own element and scalar")
                .isEqualTo(Step.FAILED);

        for (int variant = 0; variant < 3; variant++) {
            EapPwd s = new EapPwd(SERVER_ID);
            Peer p = new Peer("alice", "pw".getBytes());
            byte[] answer = p.commit(
                    s.process(1, p.idResponse(s.start(1, c).request()), c).request());
            switch (variant) {
                case 0 -> Arrays.fill(answer, 65, 97, (byte) 0); // scalar 0
                case 1 -> System.arraycopy(P256.bytes(P256.N), 0, answer, 65, 32); // scalar = order
                default -> answer[64] ^= 1; // the element off the curve
            }
            assertThat(s.process(2, answer, c)).as("variant " + variant).isEqualTo(Step.FAILED);
        }

        EapPwd s = new EapPwd(SERVER_ID);
        byte[] id = new Peer("alice", "pw".getBytes()).idResponse(s.start(1, c).request());
        id[5] ^= 1;
        assertThat(s.process(1, id, c)).as("another token").isEqualTo(Step.FAILED);
        assertThat(new EapPwd(SERVER_ID).process(1, new byte[] {2}, c))
                .as("out of order")
                .isEqualTo(Step.FAILED);
        assertThat(new EapPwd(SERVER_ID).process(1, new byte[0], c)).isEqualTo(Step.FAILED);
    }

    @Test
    void fragmentsAreAcknowledgedAndJoined() {
        Credentials c = cleartext("pw", true);
        EapPwd server = new EapPwd(SERVER_ID);
        Peer peer = new Peer("alice", "pw".getBytes());
        byte[] whole = peer.idResponse(server.start(1, c).request());
        byte[] first = new byte[3 + 5];
        first[0] = (byte) (0x80 | 0x40 | 1); // L, M, ID exchange; then a 2-byte total length
        first[2] = (byte) (whole.length - 1);
        System.arraycopy(whole, 1, first, 3, 5);
        Step ack = server.process(1, first, c);
        assertThat(ack.request()).containsExactly(1);
        byte[] rest = new byte[1 + whole.length - 6];
        rest[0] = 1;
        System.arraycopy(whole, 6, rest, 1, whole.length - 6);
        Step commit = server.process(2, rest, c);
        assertThat(commit.request()[0])
                .as("the Commit after the joined ID response")
                .isEqualTo((byte) 2);
    }

    @Test
    void p256() {
        assertThat(P256.onCurve(P256.G)).isTrue();
        assertThat(P256.multiply(P256.G, P256.N)).as("n·G is infinity").isNull();
        P256.Point twoG = P256.multiply(P256.G, BigInteger.TWO);
        assertThat(P256.add(P256.G, P256.G)).isEqualTo(twoG);
        assertThat(P256.add(twoG, P256.negate(twoG))).isNull();
        assertThat(P256.add(null, P256.G)).isEqualTo(P256.G);
        assertThat(P256.multiply(P256.G, BigInteger.valueOf(5)))
                .isEqualTo(P256.add(twoG, P256.multiply(P256.G, BigInteger.valueOf(3))));
        byte[] encoded = twoG.encode();
        assertThat(P256.decode(encoded, 0)).isEqualTo(twoG);
        byte[] outOfRange = encoded.clone();
        System.arraycopy(P256.bytes(P256.P), 0, outOfRange, 0, 32);
        assertThat(P256.decode(outOfRange, 0)).isNull();
        assertThat(P256.isQuadraticResidue(BigInteger.ZERO)).isFalse();
        assertThat(EapPwd.kdf(new byte[32], new byte[] {1}, 12)[1] & 0x0F)
                .as("bits beyond the length masked")
                .isZero();
    }
}
