# ADR 0039: PEAP versions, client certificates, and a comparison with an external server

Status: Accepted (2026-11-10). Phase 5, work package 5.15 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
PEAP (ADR 0029) has a version in the low bits of its flags. Version 0 is Microsoft's PEAP, which every current
supplicant uses: Windows, macOS and iOS, Android and ChromeOS (wpa_supplicant), and Linux. Version 1 is an older
draft whose only notable users were Cisco's PEAP/EAP-GTC clients. It differs in:
- the inner EAP framing (full headers);
- the result (a tunneled EAP-Success instead of the Result TLV);
- the key label (`client EAP encryption` or `client PEAP encryption`, depending on the client);
- no crypto-binding, and no definition for TLS 1.3.

The established open-source RADIUS server offers version 0 only, in its 3.x and its 4.x development line. It steps
down if a peer answers with a lower version, of which there is none. The gateway also offered version 0, but ignored
the version bits a peer sent back. That server can also require a client certificate inside PEAP
(`require_client_cert`); the gateway could not.

What matters to an operator moving from such a server is that the same supplicants end the same way. That can be
tested rather than claimed.

## Decision
- **PEAPv1 is not planned.** The gateway offers PEAPv0, like the server it is compared with. It will be reconsidered
  if a user with PEAPv1 clients (old Cisco PEAP/GTC) asks for it. The outline is kept here:
  - an opt-in setting that offers v1 and accepts a peer's 0 or 1;
  - full inner EAP headers and a tunneled EAP-Success;
  - the key label as a setting;
  - TLS 1.2 only, set on the engine once the peer's version is known.
- **Version bits are checked**: PEAP and TTLS offer version 0, and a peer answering with a higher one fails the
  conversation at once. RFC 5281 §9.1 defines only TTLSv0, and a PEAPv1-only peer cannot follow PEAPv0. EAP-TLS has
  no version; its reserved bits are ignored on receipt (RFC 5216 §3.1).
- **`auth.eap.peap.client.certificate`** (default `false`): PEAP's TLS handshake requires a client certificate that
  chains to `auth.eap.tls.ca`, with its revocation settings (ADR 0033). The inner method still runs: the certificate
  is in addition to the password, not instead of it. Without `auth.eap.tls.ca` this is a configuration error.
- **Comparison test**: `ExternalEapComparisonIT` (`-Pinterop`, Docker) runs the same `eapol_test` profiles against an
  installed `radiusd` and against the gateway.
  - Both servers use the same users file, certificates and secret.
  - The external server is configured with EAP-TLS, PEAP (MS-CHAPv2 and GTC inside) and TTLS, and a persistent TLS
    session cache so that it resumes.
  - Each profile must end the same way on both, with the MS-MPPE keys matching the peer's MSK when accepted.
  - Where one resumes the other must too, and PEAP fast reconnect must need as many inner MS-CHAPv2 rounds on both.

## Consequences
- A peer that answers PEAP or TTLS with a version the server did not offer is rejected at its first message. A
  wpa_supplicant forced to `peapver=1` already gives up by itself against either server.
- Sites that require device certificates for PEAP (managed laptops plus user passwords) can do so as before.
- The comparison covers:
  - PEAPv0/MS-CHAPv2 over TLS 1.2 and 1.3, PEAPv0/GTC, a peer leaving the version to the server, a wrong password,
    a peer forced to PEAPv1;
  - TTLS with PAP and MS-CHAPv2 and a wrong password;
  - EAP-TLS over TLS 1.2 and 1.3;
  - each authenticated twice on one TLS session;
  - PEAP with a required client certificate, with and without one.

  A difference found later becomes a profile there.
- Not compared: features of that server the gateway does not have, namely SoH (Microsoft NAP, removed from Windows)
  and proxying the inner request of a tunnel to a home server (the gateway proxies whole EAP conversations by the
  outer realm, ADR 0037).

## Tests
- `EapTlsTest`:
  - a peer claiming PEAPv1 or TTLSv1 is rejected, the same peers with version 0 are accepted;
  - EAP-TLS ignores its reserved bits;
  - PEAP with `client.certificate` rejects no certificate, a certificate of another CA, and the right certificate
    with a wrong password, and accepts the right certificate with the right password;
  - configuration keys and the missing-CA error.
- `ExternalEapComparisonIT` as above; each run's `eapol_test` output and the external server's log are kept in
  `gateway/target/eap-comparison`.
