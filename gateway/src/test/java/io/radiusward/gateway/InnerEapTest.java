/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.gateway.EapMethod.Credentials;
import io.radiusward.gateway.EapMethod.Inner;
import io.radiusward.gateway.EapMethod.Step;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The EAP conversation inside TTLS (ADR 0040): Identity, EAP-MD5, EAP-GTC, EAP-MSCHAPv2, Naks, unavailable checks. */
class InnerEapTest {

    static final String PASSWORD = "Alice-Pw";

    /** Checks against alice's cleartext password; {@code down} answers DROP, as an unreachable store does. */
    static final class Checks implements EapMethod.InnerAuth {
        boolean down;
        int calls;

        @Override
        public Inner password(String user, byte[] password) {
            calls++;
            if (down) {
                return new Inner(AccessHandler.DROP, null);
            }
            boolean ok = user.equals("alice") && Arrays.equals(password, PASSWORD.getBytes(StandardCharsets.UTF_8));
            return new Inner(ok ? AccessHandler.ACCEPT : AccessHandler.REJECT, null);
        }

        @Override
        public Inner chap(String user, int identifier, byte[] challenge, byte[] response) {
            calls++;
            if (down) {
                return new Inner(AccessHandler.DROP, null);
            }
            return new Inner(
                    user.equals("alice") && MessageDigest.isEqual(md5(identifier, PASSWORD, challenge), response)
                            ? AccessHandler.ACCEPT
                            : AccessHandler.REJECT,
                    null);
        }

        @Override
        public Inner msChapV2(String user, EapMethod.MsChapV2 exchange) {
            calls++;
            byte[] ntHash = MsChap.ntHash(PASSWORD);
            return user.equals("alice")
                            && MessageDigest.isEqual(
                                    MsChap.challengeResponse(exchange.challengeHash(), ntHash), exchange.ntResponse())
                    ? new Inner(AccessHandler.ACCEPT, Md4.digest(ntHash))
                    : new Inner(AccessHandler.REJECT, null);
        }
    }

    private final Checks checks = new Checks();
    private final Credentials credentials = new Credentials(List.of(), false, checks);

    static byte[] md5(int identifier, String password, byte[] challenge) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update((byte) identifier);
            md.update(password.getBytes(StandardCharsets.UTF_8));
            md.update(challenge);
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] response(int identifier, int type, byte[] data) {
        return new EapPacket(EapPacket.CODE_RESPONSE, identifier, type, data).encode();
    }

    private static EapPacket request(Step step) {
        assertThat(step.done()).as("another inner request").isFalse();
        EapPacket p = EapPacket.parse(step.request());
        assertThat(p.code()).isEqualTo(EapPacket.CODE_REQUEST);
        return p;
    }

    private EapPacket identity(InnerEap inner, String user) {
        return request(
                inner.handle(response(7, EapPacket.TYPE_IDENTITY, user.getBytes(StandardCharsets.UTF_8)), credentials));
    }

    @Test
    void md5WithTheRightAndAWrongPassword() {
        for (String password : List.of(PASSWORD, "wrong")) {
            InnerEap inner = new InnerEap(List.of(InnerEap.MD5));
            EapPacket challenge = identity(inner, "alice");
            assertThat(challenge.type()).isEqualTo(InnerEap.MD5);
            byte[] c = Arrays.copyOfRange(challenge.data(), 1, 17);
            byte[] answer = new byte[17];
            answer[0] = 16;
            System.arraycopy(md5(challenge.identifier(), password, c), 0, answer, 1, 16);
            Step step = inner.handle(response(challenge.identifier(), InnerEap.MD5, answer), credentials);
            assertThat(step.done()).isTrue();
            assertThat(step.success()).as(password).isEqualTo(password.equals(PASSWORD));
        }
        assertThat(new InnerEap(List.of(InnerEap.MD5)).identity()).isNull();
    }

    @Test
    void gtcChosenByNakAndCheckedLikePap() {
        InnerEap inner = new InnerEap(List.of(InnerEap.MS_CHAP_V2, InnerEap.GTC));
        EapPacket first = identity(inner, "alice");
        assertThat(first.type()).isEqualTo(InnerEap.MS_CHAP_V2);
        EapPacket gtc = request(inner.handle(
                response(first.identifier(), EapPacket.TYPE_NAK, new byte[] {(byte) InnerEap.GTC}), credentials));
        assertThat(gtc.type()).isEqualTo(InnerEap.GTC);
        Step step = inner.handle(
                response(gtc.identifier(), InnerEap.GTC, PASSWORD.getBytes(StandardCharsets.UTF_8)), credentials);
        assertThat(step.success()).isTrue();
        assertThat(inner.identity()).isEqualTo("alice");
    }

    @Test
    void aNakForNothingOfferedOrAStrayResponseFails() {
        InnerEap inner = new InnerEap(List.of(InnerEap.GTC));
        EapPacket first = identity(inner, "alice");
        assertThat(inner.handle(response(first.identifier(), EapPacket.TYPE_NAK, new byte[] {13}), credentials))
                .isEqualTo(Step.FAILED);

        InnerEap other = new InnerEap(List.of(InnerEap.GTC));
        EapPacket gtc = identity(other, "alice");
        assertThat(other.handle(response(gtc.identifier() + 1, InnerEap.GTC, new byte[] {1}), credentials))
                .as("another identifier")
                .isEqualTo(Step.FAILED);
        assertThat(new InnerEap(List.of(InnerEap.GTC)).handle(response(1, InnerEap.GTC, new byte[] {1}), credentials))
                .as("no identity first")
                .isEqualTo(Step.FAILED);
        assertThat(new InnerEap(List.of(InnerEap.GTC)).handle(new byte[] {2, 1, 0}, credentials))
                .as("malformed")
                .isEqualTo(Step.FAILED);
    }

    @Test
    void anUnavailableCheckIsRepeatedForTheRetransmission() {
        InnerEap inner = new InnerEap(List.of(InnerEap.GTC));
        EapPacket gtc = identity(inner, "alice");
        checks.down = true;
        byte[] answer = response(gtc.identifier(), InnerEap.GTC, PASSWORD.getBytes(StandardCharsets.UTF_8));
        assertThat(inner.handle(answer, credentials).unavailable()).isTrue();
        assertThat(inner.retry(credentials).unavailable()).isTrue();
        checks.down = false;
        assertThat(inner.retry(credentials).success()).isTrue();
        assertThat(checks.calls).isEqualTo(3);
        assertThat(new InnerEap(List.of(InnerEap.GTC)).retry(credentials)).isEqualTo(Step.FAILED);
    }

    @Test
    void msChapV2EndsWithASuccessRequestThePeerAcknowledges() {
        for (String password : List.of(PASSWORD, "wrong")) {
            InnerEap inner = new InnerEap(List.of(InnerEap.MS_CHAP_V2));
            EapPacket challenge = identity(inner, "alice");
            byte[] d = challenge.data(); // opcode 1, id, MS-length, 16, challenge 16, name
            int msChapId = d[1] & 0xFF;
            byte[] authenticatorChallenge = Arrays.copyOfRange(d, 5, 21);
            byte[] peerChallenge = new byte[16];
            Arrays.fill(peerChallenge, (byte) 7);
            byte[] name = "alice".getBytes(StandardCharsets.UTF_8);
            byte[] hash = MsChap.challengeHash(peerChallenge, authenticatorChallenge, name);
            byte[] nt = MsChap.challengeResponse(hash, MsChap.ntHash(password));
            byte[] answer = new byte[4 + 1 + 49 + name.length];
            answer[0] = 2;
            answer[1] = (byte) msChapId;
            answer[3] = (byte) answer.length;
            answer[4] = 49;
            System.arraycopy(peerChallenge, 0, answer, 5, 16);
            System.arraycopy(nt, 0, answer, 29, 24);
            System.arraycopy(name, 0, answer, 54, name.length);
            Step step = inner.handle(response(challenge.identifier(), InnerEap.MS_CHAP_V2, answer), credentials);
            if (!password.equals(PASSWORD)) {
                assertThat(step).isEqualTo(Step.FAILED);
                continue;
            }
            EapPacket success = request(step);
            assertThat(success.data()[0]).as("Success request").isEqualTo((byte) 3);
            assertThat(new String(success.data(), StandardCharsets.US_ASCII)).contains("S=");
            assertThat(inner.handle(response(success.identifier(), InnerEap.MS_CHAP_V2, new byte[] {3}), credentials)
                            .success())
                    .isTrue();
        }
    }
}
