# ADR 0042: EAP-pwd

Status: Accepted (2026-11-10). Phase 5, work package 5.18 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
EAP-pwd (RFC 5931) authenticates both sides with a password alone: no server certificate to provision or validate,
and no offline dictionary attack from a captured exchange. Hotspot 2.0 profiles and some IoT supplicants use it, and
wpa_supplicant and other RADIUS servers support it.

## Decision
- **Method 52**, group 19 (NIST P-256) with random function and PRF 1 (HMAC-SHA256) only, as wpa_supplicant and
  other servers offer by default.
- **Messages**:
  - ID exchange: the server offers the group, a random token, the password preparation and its identity
    (`auth.eap.pwd.server.id`, default `radiusward`); the peer echoes them and names itself.
  - Commit: element and scalar.
  - Confirm: H over the shared secret, both commits and the ciphersuite.
  - Fragments from the peer are acknowledged and joined, up to 4 KiB; the server's own messages always fit in one.
- **Password preparation**, from what the store holds:
  - *none*, with the cleartext of a store that allows cleartext (`auth.store.<name>.chap`, as for CHAP and
    EAP-MD5);
  - otherwise *MS*, with MD4 of the NT hash (`NT-Password`).
  - A user with neither is rejected.
- **Computation** (RFC 5931 as wpa_supplicant and hostapd implement it):
  - H is HMAC-SHA256 with a zero key; the KDF is the counter-mode HMAC-SHA256 of §2.5.
  - The password element comes from hunting and pecking over pwd-seed = H(token | peer-id | server-id | password |
    counter), with the y coordinate's parity from the seed.
  - The server's scalar and element come from a random private value and mask.
  - The peer's commit is checked: scalar in (1, n), element on the curve, not a reflection of ours, a non-zero shared
    point.
  - MK = H(k | Confirm_peer | Confirm_server); MSK and EMSK = KDF(MK, type 52 | H(ciphersuite | peer scalar |
    server scalar), 1024 bits).
- **Arithmetic**: `P256`, affine and Jacobian points on `BigInteger`, because the JDK has no public point arithmetic.
  - Hunting and pecking always runs all 40 rounds, and multiplication is a fixed ladder over all 256 bits, so the
    sequence of operations does not depend on the password or the secret values.
  - `BigInteger` is not constant-time. A local attacker able to time the gateway's CPU precisely could learn more
    than from the protocol. Where that matters, prefer EAP-TLS, PEAP or TEAP; their private-key work runs in the
    JDK's constant-time implementations.
- **Not covered**: other groups (Brainpool, P-384/521), salted password preparations (SSHA*), EAP-pwd fast
  reconnect.

## Tests
- `EapPwdTest`, against a peer written from RFC 5931 in the test:
  - success with the cleartext and with an NT hash; wrong passwords;
  - a store without usable credentials;
  - a reflected commit; scalars 0 and n; an element off the curve; a wrong token;
  - out-of-order and empty messages; peer fragments acknowledged and joined;
  - the ID request's fields;
  - P-256 identities (n·G, addition and doubling, negation, decoding).
- `EapolTestIT#pwd`: wpa_supplicant 2.12 with alice's cleartext and bob's NT hash, and wrong passwords for both.
- `ExternalEapComparisonIT`: the same outcome and matching keys on an external RADIUS server and on the gateway.
