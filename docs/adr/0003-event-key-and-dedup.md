# ADR 0003: Logical event key and per-session deduplication

Status: Accepted (2026-11-07)

## Context
A NAS retransmits when a response is lost, possibly through another gateway, possibly with a new
Identifier and an updated `Acct-Delay-Time` (which changes the Request Authenticator). Keeping one dedup
entry per event for 24 h would need ~285M entries at 3.3k req/s — impossible in 1 GiB.

## Decision
- **Gateway:** RFC 5080 response cache keyed by source address, Identifier and Request Authenticator,
  plus attaching duplicates of in-flight requests.
- **Cluster:** a logical event key = NAS identity + `Acct-Session-Id` + `Acct-Status-Type` +
  (`Acct-Session-Time` | `Event-Timestamp`), **excluding** `Acct-Delay-Time` and the Identifier; a
  pluggable `EventKeyStrategy` per vendor profile (Cisco, Juniper, MikroTik, Huawei, Meraki, Ruckus).
- **Per-session dedup:** store the last applied (status type, session time, counters) per session; an
  event that is not newer is a duplicate. Stop leaves a tombstone for a window; events without a
  monotonic field use a small exact-key window (default 15 min).
- All dedup expiry uses **cluster time**.

## Consequences
- Memory grows with concurrent sessions (~80 B each; 500k sessions ≈ 40 MB), not with event volume.
- A retransmit older than the exact-key window could be applied twice; sinks are idempotent by
  `event_id` as a second guard.
- Vendor quirks live in strategies tested with the vendor fixtures.
