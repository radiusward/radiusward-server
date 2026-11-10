/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Arithmetic on NIST P-256 (secp256r1, EAP-pwd group 19) for EAP-pwd (ADR 0042): the JDK has no public point
 * arithmetic. Points are affine {@code (x, y)}; {@code null} is the point at infinity. Multiplication works in Jacobian
 * coordinates with a fixed double-and-add ladder over all 256 bits, so its sequence of operations does not depend on
 * the scalar; {@link BigInteger} itself is not constant-time (see ADR 0042).
 */
final class P256 {

    static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    static final Point G = new Point(
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));
    static final int FIELD_BYTES = 32;

    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger SQRT_EXPONENT = P.add(BigInteger.ONE).shiftRight(2); // p = 3 mod 4
    private static final BigInteger LEGENDRE_EXPONENT =
            P.subtract(BigInteger.ONE).shiftRight(1);

    private P256() {}

    /** An affine point. */
    record Point(BigInteger x, BigInteger y) {

        /** x and y, 32 bytes each. */
        byte[] encode() {
            byte[] out = new byte[2 * FIELD_BYTES];
            System.arraycopy(bytes(x), 0, out, 0, FIELD_BYTES);
            System.arraycopy(bytes(y), 0, out, FIELD_BYTES, FIELD_BYTES);
            return out;
        }
    }

    /** A number as exactly 32 big-endian bytes. */
    static byte[] bytes(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[FIELD_BYTES];
        int n = Math.min(raw.length, FIELD_BYTES);
        System.arraycopy(raw, raw.length - n, out, FIELD_BYTES - n, n);
        return out;
    }

    /** A point from x and y (32 bytes each), or {@code null} if a coordinate is out of range or it is off the curve. */
    static Point decode(byte[] data, int offset) {
        BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(data, offset, offset + FIELD_BYTES));
        BigInteger y =
                new BigInteger(1, java.util.Arrays.copyOfRange(data, offset + FIELD_BYTES, offset + 2 * FIELD_BYTES));
        if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
            return null;
        }
        Point point = new Point(x, y);
        return onCurve(point) ? point : null;
    }

    /** y² for x: x³ + ax + b mod p. */
    static BigInteger ySquared(BigInteger x) {
        return x.pow(3).add(A.multiply(x)).add(B).mod(P);
    }

    static boolean onCurve(Point q) {
        return q != null && q.y.multiply(q.y).mod(P).equals(ySquared(q.x));
    }

    /** Whether v is a non-zero quadratic residue mod p (Euler's criterion). */
    static boolean isQuadraticResidue(BigInteger v) {
        return v.signum() != 0 && v.modPow(LEGENDRE_EXPONENT, P).equals(BigInteger.ONE);
    }

    /** A square root mod p of a quadratic residue. */
    static BigInteger sqrt(BigInteger v) {
        return v.modPow(SQRT_EXPONENT, P);
    }

    static Point negate(Point q) {
        return q == null ? null : new Point(q.x, P.subtract(q.y).mod(P));
    }

    static Point add(Point a, Point b) {
        return toAffine(addJ(toJacobian(a), toJacobian(b)));
    }

    /** k·Q: a ladder over all 256 bits, one doubling and one addition each. */
    static Point multiply(Point q, BigInteger k) {
        BigInteger[] r0 = null; // infinity
        BigInteger[] r1 = toJacobian(q);
        for (int i = 255; i >= 0; i--) {
            if (k.testBit(i)) {
                r0 = addJ(r0, r1);
                r1 = doubleJ(r1);
            } else {
                r1 = addJ(r0, r1);
                r0 = doubleJ(r0);
            }
        }
        return toAffine(r0);
    }

    /** A random scalar in [1, n). */
    static BigInteger randomScalar(SecureRandom random) {
        BigInteger k;
        do {
            k = new BigInteger(256, random);
        } while (k.signum() == 0 || k.compareTo(N) >= 0);
        return k;
    }

    private static BigInteger[] toJacobian(Point q) {
        return q == null ? null : new BigInteger[] {q.x, q.y, BigInteger.ONE};
    }

    private static Point toAffine(BigInteger[] j) {
        if (j == null || j[2].signum() == 0) {
            return null;
        }
        BigInteger zInv = j[2].modInverse(P);
        BigInteger zInv2 = zInv.multiply(zInv).mod(P);
        return new Point(
                j[0].multiply(zInv2).mod(P), j[1].multiply(zInv2).multiply(zInv).mod(P));
    }

    private static BigInteger[] doubleJ(BigInteger[] q) {
        if (q == null || q[1].signum() == 0) {
            return null;
        }
        BigInteger x = q[0], y = q[1], z = q[2];
        BigInteger z2 = z.multiply(z).mod(P);
        BigInteger m = THREE.multiply(x.subtract(z2)).multiply(x.add(z2)).mod(P); // a = -3
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger s = BigInteger.valueOf(4).multiply(x).multiply(y2).mod(P);
        BigInteger x3 = m.multiply(m).subtract(TWO.multiply(s)).mod(P);
        BigInteger y3 = m.multiply(s.subtract(x3))
                .subtract(BigInteger.valueOf(8).multiply(y2).multiply(y2))
                .mod(P);
        BigInteger z3 = TWO.multiply(y).multiply(z).mod(P);
        return new BigInteger[] {x3, y3, z3};
    }

    private static BigInteger[] addJ(BigInteger[] a, BigInteger[] b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        BigInteger z1z1 = a[2].multiply(a[2]).mod(P);
        BigInteger z2z2 = b[2].multiply(b[2]).mod(P);
        BigInteger u1 = a[0].multiply(z2z2).mod(P);
        BigInteger u2 = b[0].multiply(z1z1).mod(P);
        BigInteger s1 = a[1].multiply(b[2]).multiply(z2z2).mod(P);
        BigInteger s2 = b[1].multiply(a[2]).multiply(z1z1).mod(P);
        if (u1.equals(u2)) {
            return s1.equals(s2) ? doubleJ(a) : null; // the same point, or each other's negative
        }
        BigInteger h = u2.subtract(u1).mod(P);
        BigInteger r = s2.subtract(s1).mod(P);
        BigInteger h2 = h.multiply(h).mod(P);
        BigInteger h3 = h2.multiply(h).mod(P);
        BigInteger u1h2 = u1.multiply(h2).mod(P);
        BigInteger x3 = r.multiply(r).subtract(h3).subtract(TWO.multiply(u1h2)).mod(P);
        BigInteger y3 = r.multiply(u1h2.subtract(x3)).subtract(s1.multiply(h3)).mod(P);
        BigInteger z3 = h.multiply(a[2]).multiply(b[2]).mod(P);
        return new BigInteger[] {x3, y3, z3};
    }
}
