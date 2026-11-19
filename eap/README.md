# eap

`radiusward-eap`: the EAP protocol primitives both sides need — the RADIUS server's EAP methods and the client's
supplicant ([ADR 0068](../docs/adr/0068-embedded-radiusward-and-maven-central.md)) — so each exists once.

| Class | Role |
|---|---|
| `EapPacket` | an EAP packet (RFC 3748): code, identifier, type, data; the method numbers; parsing, encoding, `EAP-Message` attributes |
| `MsChap` | MS-CHAPv1/v2 (RFC 2433, RFC 2759): NT hash, challenge response, authenticator response, MPPE keys and their RFC 2548 encryption |
| `PeapCryptoBinding` | PEAPv0 crypto-binding (MS-PEAP §3.1.5.5): the server's TLV and its check, the peer's answer, the compound MSK |
| `TtlsAvp` | an EAP-TTLS AVP (RFC 5281 §10.1) |
| `TeapKeys` | TEAP's key hierarchy (RFC 7170, RFC 9930) |
| `P256` | NIST P-256 arithmetic for EAP-pwd (RFC 5931) |
| `Milenage`, `SimKeys`, `SimMessage`, `SimVectors` | MILENAGE and GSM-MILENAGE, EAP-SIM/AKA/AKA′ key derivation and messages (RFC 4186, RFC 4187, RFC 9048) |

No state, no threads, no I/O: plain functions of their inputs, tested against the RFCs' and 3GPP's vectors here and end
to end through the server's EAP tests and the client's supplicant (`EapSupplicantIT`).
