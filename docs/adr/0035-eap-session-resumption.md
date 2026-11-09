# ADR 0035: EAP session resumption and fast reconnect

Status: Accepted (2026-11-09). Phase 5, work package 5.11 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Devices roaming between access points authenticate again and again. A full TLS handshake costs the gateway a
private-key operation and the device several round trips. Inside PEAP and TTLS it also costs another inner check,
for example a Netlogon round trip to a domain controller. Peers offer to resume their previous TLS session, and
wpa_supplicant's TTLS even skips its inner phase when the session is resumed.

`eapol_test -r 1` (a second authentication on the same session) showed that the JDK already resumed sessions.
- TLS 1.3 worked.
- Every TLS 1.2 resumption failed. In the abbreviated handshake the client's Finished comes last, but the tunnel
  still waited for the client to acknowledge our Finished.

## Decision
- **Resumption** of EAP-TLS, PEAP and TTLS sessions (TLS 1.2 session IDs, TLS 1.3 PSK) within
  `auth.eap.tls.session.timeout` (default 1 h).
  - Sessions live in the gateway's session cache (ADR 0034: the JDK does not check the age of stateless tickets), so
    resumption works per gateway. A device that reaches another gateway gets a full handshake.
  - A handshake is resumed when its session is older than the conversation.
  - After a resumed TLS 1.2 handshake, which ends with the client's Finished, the method continues at once.
  - `radiusward_gateway_eap_tls_resumptions_total` counts resumptions.
- **EAP-TLS**: the resumed session keeps the client certificate. Its names are checked against the identity again
  (ADR 0033), and the user is authorized as usual. Revocation is not checked again until the session expires.
- **Fast reconnect for PEAP and TTLS**: the inner user who authenticated in the session's first conversation is
  remembered with the TLS session, on the gateway only.
  - PEAP: a resumed tunnel goes straight to the Result TLV.
  - TTLS: a resumed tunnel succeeds as soon as the handshake ends (RFC 5281 §8).
  - The remembered user is then authorized again like any inner user. A user disabled or rejected in the store meanwhile is rejected,
    once the per-worker cache (`auth.cache.ttl`) has expired.
  - A password change is not noticed until the session expires.
- **Crypto-binding on fast reconnect**: no inner method ran, so IPMK and CMK are the tunnel key itself (bytes 0–40
  and 40–60). That is how wpa_supplicant derives them; PRF+ over an inner key would not verify.
- **A failed conversation invalidates its session**, so a peer cannot resume a session whose inner method or
  certificate check failed.

## Consequences
- Re-authentication of a device with a session costs one round trip of TLS and no inner check.
- `auth.eap.tls.session.timeout` bounds three things for that long: a revoked certificate, a changed password, and
  inner credentials that are no longer checked. Shorten it where that matters.
- Interop with `eapol_test` covers resumption of EAP-TLS, PEAP (with crypto-binding required) and TTLS on TLS 1.2
  and 1.3. Each time the second authentication's MPPE keys match the peer's MSK, and PEAP shows a single inner
  exchange.
