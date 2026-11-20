# radiusward-eap

`radiusward-eap` holds the EAP protocol primitives that both sides of an EAP exchange need: the RADIUS server's EAP
methods and the client's supplicant. Each calculation exists once, so the server and the test client cannot drift
apart: the EAP packet, MS-CHAP, PEAP crypto-binding, TTLS AVPs, TEAP keys, EAP-pwd on P-256, MILENAGE and the
EAP-SIM/AKA/AKA′ keys and messages ([ADR 0068](../docs/adr/0068-embedded-radiusward-and-maven-central.md)).

**Stability:** Internal: published as a dependency of `radiusward-client` and the radiusward server; it may change in any release.

## Use it

You normally do not depend on it directly: `radiusward-client` brings it for its EAP supplicant (PEAP, TTLS, TEAP,
TLS, pwd, SIM, AKA), and `radiusward-embedded` and the radiusward server bring it for the EAP methods. Identity store
and credential verifier writers use `radiusward-auth-api` instead.

## What's inside

| Type | Role |
|---|---|
| `EapPacket` | an EAP packet (RFC 3748): code, identifier, type, data; the method numbers; `parse`, `encode`, `from(RadiusPacket)` joining the `EAP-Message` attributes (RFC 3579), `writeTo` an encoder |
| `MsChap` | MS-CHAPv1/v2 (RFC 2433, RFC 2759): NT hash, challenge response, authenticator response, MPPE keys (RFC 3079) and their RFC 2548 encryption; verification only, from the NT hash |
| `PeapCryptoBinding` | PEAPv0 crypto-binding (MS-PEAP §3.1.5.5): the server's TLV and its check, the peer's answer, the compound MSK ([ADR 0032](../docs/adr/0032-peap-crypto-binding.md)) |
| `TtlsAvp` | an EAP-TTLS AVP (RFC 5281 §10.1): code, flags, vendor, value padded to four bytes |
| `TeapKeys`, `TeapTlv` | TEAP's key hierarchy (RFC 7170, RFC 9930); its TLV types, Result values and encoding ([ADR 0041](../docs/adr/0041-teap.md)) |
| `P256`, `EapPwdKeys` | NIST P-256 arithmetic (the JDK has no public point arithmetic); EAP-pwd's password element, H, KDF, Confirm values and MSK for group 19 (RFC 5931, [ADR 0042](../docs/adr/0042-eap-pwd.md)) |
| `Milenage`, `SimKeys`, `SimMessage`, `SimVectors` | MILENAGE (3GPP TS 35.206) and GSM-MILENAGE (TS 55.205); EAP-SIM/AKA/AKA′ key derivation and messages (RFC 4186, RFC 4187, RFC 9048, [ADR 0061](../docs/adr/0061-eap-sim-aka.md)) |

No state, no threads, no I/O: plain functions of their inputs. Malformed input yields `null` (`EapPacket.parse`,
`SimMessage`), never an exception. Tested against the RFCs' and 3GPP's vectors here, and end to end through the
server's EAP tests and the client's supplicant (`EapSupplicantIT`).

## Example

An MS-CHAPv2 exchange as both sides compute it:

```java
byte[] ntHash     = MsChap.ntHash("secret");
byte[] challenge  = MsChap.challengeHash(peerChallenge, authenticatorChallenge, MsChap.v2UserName(userName));
byte[] ntResponse = MsChap.challengeResponse(challenge, ntHash);
String success    = MsChap.authenticatorResponse(ntHash, ntResponse, challenge);   // "S=" and 40 hex digits
byte[] masterKey  = MsChap.masterKey(ntHash, ntResponse);                           // for the MPPE keys

EapPacket identity = EapPacket.response(1, EapPacket.TYPE_IDENTITY, "alice".getBytes(StandardCharsets.UTF_8));
byte[] wire = identity.encode();
```

## Requirements

Java 25. Runtime dependencies: `radiusward-codec` (EAP-Message attributes) and `radiusward-auth-api` (MD4 for
MS-CHAP); no third-party libraries beyond theirs.

## Learn more

- [ADR 0026: EAP framework](../docs/adr/0026-eap-framework.md), [ADR 0029: PEAP](../docs/adr/0029-peap.md),
  [ADR 0030: TTLS](../docs/adr/0030-ttls.md), [ADR 0024: MS-CHAP and Status-Server](../docs/adr/0024-ms-chap-and-status-server.md)
- [EAP-SIM/AKA plan](../docs/plans/eap-sim-aka.md)
- [radiusward-client](../client/README.md): the supplicant built on these primitives

## License

Apache-2.0.
