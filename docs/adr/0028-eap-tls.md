# ADR 0028: EAP-TLS

Status: Accepted (2026-11-09). Phase 5, work package 5.8, milestone 2 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
EAP-TLS (RFC 5216; TLS 1.3: RFC 9190) authenticates devices by their certificate and is the method Microsoft and
others recommend for Wi-Fi, including with Entra ID. It is also the base of PEAP and TTLS: a TLS handshake carried in
EAP messages, fragmented to fit RADIUS, with keys for the NAS derived from the TLS session.

## Decision
- **TLS from the JDK** (`SSLEngine`, decision 3 of the plan): server chain and unencrypted PKCS#8 key from PEM files
  (`auth.eap.tls.certificate`, `auth.eap.tls.key`), client certificates checked against `auth.eap.tls.ca` and
  required; TLS 1.2 and 1.3 (`auth.eap.tls.versions`). No Bouncy Castle at runtime.
- **Framing** (RFC 5216 §2.1.5): our messages go out in fragments of `auth.eap.tls.fragment.size` (1024), the first
  with the L flag and the total length, all but the last with M; the peer acknowledges each. The peer's fragments are
  acknowledged and joined up to `auth.eap.tls.max.message` (64 KiB); a TLS error fails the conversation
  (EAP-Failure).
- **End**: success once the server's last flight is acknowledged — TLS 1.2: its Finished; TLS 1.3: the one-byte
  commitment message after the client's Finished (RFC 9190 §2.5).
- **Keys** with the JDK 25 exporter (ADR 0027): 128 bytes, label `client EAP encryption` without context (TLS 1.2,
  the RFC 5216 PRF) or `EXPORTER_EAP_TLS_Key_Material` with the type 13 as context (TLS 1.3); MSK = the first 64
  bytes, sent as MS-MPPE-Recv-Key (MSK[0..32]) and MS-MPPE-Send-Key (MSK[32..64]).
- **Users**: a valid client certificate is the credential. A peer whose identity is in no store is accepted with no
  extra items unless `auth.eap.tls.require.user = true`; a store entry still applies its check items (e.g.
  `Auth-Type := Reject` blocks a device) and reply items.

## Consequences
- Certificate revocation (CRL/OCSP), reload of changed certificate files and matching the identity against the
  certificate come with milestone 5; until then, a compromised device is blocked through its store entry.
- Tested with a JDK TLS client as the peer, TLS 1.2 and 1.3, small fragments both ways, keys compared with the
  client's own export; interop with `eapol_test` follows in milestone 5.
