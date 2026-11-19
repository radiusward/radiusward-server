/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.eap;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class P256Test {

    @Test
    void theGeneratorIsOnTheCurveAndItsOrderIsN() {
        assertThat(P256.onCurve(P256.G)).isTrue();
        assertThat(P256.multiply(P256.G, P256.N))
                .as("n·G is the point at infinity")
                .isNull();
        assertThat(P256.multiply(P256.G, BigInteger.ONE)).isEqualTo(P256.G);
    }

    @Test
    void additionAndMultiplicationAgree() {
        BigInteger a = P256.randomScalar(new SecureRandom());
        BigInteger b = P256.randomScalar(new SecureRandom());
        P256.Point sum = P256.add(P256.multiply(P256.G, a), P256.multiply(P256.G, b));
        assertThat(sum).isEqualTo(P256.multiply(P256.G, a.add(b).mod(P256.N)));
        assertThat(P256.onCurve(sum)).isTrue();
        assertThat(P256.add(P256.G, P256.negate(P256.G))).as("G + (−G)").isNull();
    }

    @Test
    void pointsSurviveTheirEncodingAndSquareRootsAreFound() {
        P256.Point q = P256.multiply(P256.G, BigInteger.valueOf(7));
        byte[] encoded = q.encode();
        assertThat(encoded).hasSize(2 * P256.FIELD_BYTES);
        assertThat(P256.decode(encoded, 0)).isEqualTo(q);
        BigInteger y2 = P256.ySquared(q.x());
        assertThat(P256.isQuadraticResidue(y2)).isTrue();
        BigInteger root = P256.sqrt(y2);
        assertThat(root.equals(q.y()) || root.equals(P256.P.subtract(q.y()))).isTrue();
        assertThat(P256.bytes(BigInteger.ONE)).hasSize(P256.FIELD_BYTES).endsWith(1);
    }
}
