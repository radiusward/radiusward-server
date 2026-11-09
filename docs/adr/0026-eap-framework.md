# ADR 0026: The EAP framework

Status: Accepted (2026-11-09). Phase 5, work package 5.7 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Wi-Fi (802.1X) and many VPNs authenticate with EAP: a conversation of several RADIUS round trips (Access-Challenge,
Access-Request) per login, carried in `EAP-Message` attributes and tied together by `State`. The TLS-based methods
(5.8) need this plumbing; it must be bounded, safe against replays, and fit the existing decision pipeline.

## Decision
- **Conversations live in the gateway that started them**, between round trips, in a table keyed by the `State` sent
  to the peer: a fresh random 16-byte token every round. Taking a conversation removes it; it goes back under a new
  token — so every `State` is good for exactly one response, and a `State` from another NAS entry is refused. The
  table is bounded (`auth.eap.conversations`), conversations expire (`auth.eap.timeout`, 30 s) and have a round
  limit; a full table means no answer. Shared by all workers: Agrona maps behind 16 lock stripes. A NAS should reach
  the same gateway for one login (source-IP affinity); on gateway loss the peer starts over.
- **Methods** implement a small interface: started after the Identity response, then given each response until they
  succeed (optionally with an MSK) or fail. `auth.eap.methods` lists the methods offered in order; a peer's Nak may
  switch to another listed one, once, before the method begins.
- **One pipeline**: every round looks the identity up and evaluates check items and groups like PAP; the method
  replaces the password check. A continuing method answers Access-Challenge with the next EAP request and `State`;
  success runs `Simultaneous-Use` and the reply items and adds EAP-Success (and MS-MPPE keys from an MSK); every EAP
  Reject carries EAP-Failure (RFC 3579). Malformed EAP is discarded; a response to an older request is not answered.
- **EAP-MD5** is the first method, to carry the plumbing: it needs the cleartext password, so it follows CHAP's
  per-store opt-in (`auth.store.<name>.chap`), and derives no keys.

## Consequences
- 5.8 adds EAP-TLS, PEAP and TTLS as methods; their TLS fragmentation (RFC 5216) lives inside the method.
- The Identity response is looked up as the user. Anonymous outer identities (PEAP, TTLS) will need the inner
  identity for the lookup; 5.8 changes when the lookup happens for those methods.
- Interop is checked with FreeRADIUS's `radeapclient`.
