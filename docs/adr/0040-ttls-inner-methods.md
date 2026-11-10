# ADR 0040: TTLS with CHAP, MS-CHAPv1 and EAP inside

Status: Accepted (2026-11-10). Phase 5, work package 5.16 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
TTLS (ADR 0030) accepted only PAP and MS-CHAPv2 inside the tunnel. RFC 5281 also defines CHAP, MS-CHAPv1, and EAP
carried in EAP-Message AVPs. Supplicants offer all of them (wpa_supplicant's `auth=CHAP`, `auth=MSCHAP`,
`autheap=...`), and other RADIUS servers answer them. A site moving to radiusward with such profiles would see TTLS
fail.

## Decision
- **CHAP** (§11.2.2) and **MS-CHAPv1** (§11.2.3) take their challenge from the tunnel, like MS-CHAPv2 (`ttls
  challenge`); a client that answers another challenge is refused.
  - CHAP and MS-CHAPv2 use 17 bytes: the challenge and the identifier.
  - MS-CHAPv1 uses an export of its own 9 bytes: under TLS 1.3 an export depends on its length (RFC 8446 §7.5), so
    the first 9 bytes of a 17-byte export are not the same.
  - CHAP is checked like CHAP outside: only with the cleartext password of a store that allows CHAP
    (`auth.store.<name>.chap`). MS-CHAPv1 is checked like MS-CHAPv1 outside: local NT hash, or a credential verifier
    such as Netlogon.
  - Both succeed at once; TTLS's keys stay the tunnel's.
- **EAP inside TTLS** (§11.2.4): EAP-Message AVPs carry whole EAP packets, several AVPs making one long packet.
  `InnerEap` runs the inner conversation:
  - the peer's Identity response;
  - then the first method of `auth.eap.ttls.inner` (default `mschapv2, gtc, md5`); a Nak picks another listed one;
  - EAP-MSCHAPv2 is checked as outside, and ends with a Success request the peer acknowledges;
  - EAP-GTC is a password, checked like PAP;
  - EAP-MD5 is the CHAP computation, so it is allowed for the same stores as CHAP;
  - an inner check that cannot be made (store or verifier down) is repeated on the peer's retransmission, as for the
    other inner methods.

  `InnerEap` is separate from PEAP's inner code, which strips the EAP header (MS-PEAP) and carries crypto-binding.
- **Not covered**: EAP-TLS inside TTLS (a certificate inside a server-only tunnel; EAP-TLS or PEAP with an inner
  certificate cover it).

## Tests
- `InnerEapTest`:
  - EAP-MD5 with the right and a wrong password;
  - EAP-GTC chosen by a Nak;
  - a Nak for nothing offered, a stray identifier, no identity first, a malformed packet;
  - an unavailable check repeated for the retransmission;
  - EAP-MSCHAPv2 ending with the acknowledged Success request.
- `EapolTestIT#ttlsInnerMethods`: wpa_supplicant over TLS 1.2 and 1.3 with `auth=CHAP`, `auth=MSCHAP`,
  `autheap=MSCHAPV2`, `autheap=MD5` and `autheap=GTC`, accepted with matching MPPE keys; each rejected with a wrong
  password.
- `ExternalEapComparisonIT`: the same profiles, with a wrong password for CHAP and EAP-MD5, end the same way on an
  external RADIUS server and on the gateway.
