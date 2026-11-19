/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/** EAP-pwd's cryptography: both sides derive the same element, Confirm values and MSK from the same password. */
class EapPwdKeysTest {

    private static final byte[] PASSWORD = "secret".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVER = "radiusward".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PEER = "alice".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TOKEN = {1, 2, 3, 4};

    @Test
    void thePasswordElementIsOnTheCurveAndTheSameEachTime() {
        P256.Point pwe = EapPwdKeys.passwordElement(PASSWORD, SERVER, PEER, TOKEN);
        assertThat(P256.onCurve(pwe)).isTrue();
        assertThat(EapPwdKeys.passwordElement(PASSWORD, SERVER, PEER, TOKEN)).isEqualTo(pwe);
        assertThat(EapPwdKeys.passwordElement(PASSWORD, SERVER, PEER, new byte[] {9, 9, 9, 9}))
                .as("another token, another element")
                .isNotEqualTo(pwe);
    }

    @Test
    void anExchangeGivesBothSidesTheSameSecretConfirmsAndMsk() {
        SecureRandom random = new SecureRandom();
        P256.Point pwe = EapPwdKeys.passwordElement(PASSWORD, SERVER, PEER, TOKEN);
        BigInteger sPrivate = P256.randomScalar(random);
        BigInteger sMask = P256.randomScalar(random);
        BigInteger sScalar = sPrivate.add(sMask).mod(P256.N);
        P256.Point sElement = P256.negate(P256.multiply(pwe, sMask));
        BigInteger pPrivate = P256.randomScalar(random);
        BigInteger pMask = P256.randomScalar(random);
        BigInteger pScalar = pPrivate.add(pMask).mod(P256.N);
        P256.Point pElement = P256.negate(P256.multiply(pwe, pMask));
        BigInteger serverK = P256.multiply(P256.add(P256.multiply(pwe, pScalar), pElement), sPrivate)
                .x();
        BigInteger peerK = P256.multiply(P256.add(P256.multiply(pwe, sScalar), sElement), pPrivate)
                .x();
        assertThat(peerK).isEqualTo(serverK);

        byte[] serverConfirm = EapPwdKeys.confirm(serverK, sElement, sScalar, pElement, pScalar);
        byte[] peerConfirm = EapPwdKeys.confirm(peerK, pElement, pScalar, sElement, sScalar);
        assertThat(peerConfirm).as("each side confirms from its own view").isNotEqualTo(serverConfirm);
        byte[] serverMsk = EapPwdKeys.msk(serverK, peerConfirm, serverConfirm, pScalar, sScalar);
        byte[] peerMsk = EapPwdKeys.msk(peerK, peerConfirm, serverConfirm, pScalar, sScalar);
        assertThat(peerMsk).hasSize(64).isEqualTo(serverMsk);
    }

    @Test
    void theKdfGivesTheBitsAskedFor() {
        byte[] key = new byte[32];
        assertThat(EapPwdKeys.kdf(key, "label".getBytes(StandardCharsets.US_ASCII), 256))
                .hasSize(32);
        byte[] odd = EapPwdKeys.kdf(key, "label".getBytes(StandardCharsets.US_ASCII), 260);
        assertThat(odd).hasSize(33);
        assertThat(odd[32] & 0x0F).as("bits beyond 260 cleared").isZero();
        assertThat(EapPwdKeys.h(new byte[] {1})).hasSize(32);
    }
}
