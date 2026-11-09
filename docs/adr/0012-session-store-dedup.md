# ADR 0012: SessionStore and the deduplication algorithm

Status: Accepted (2026-11-08). Details for ADR 0003.

## Decision
**Storage.** Sessions are columns of primitive arrays in chunks of 16,384 slots (4 long, 8 int, 3 byte
columns = 67 bytes) plus an open-addressing `int[]` index on the 128-bit session key (linear probing,
backward-shift delete). No object per session; allocation only for a new chunk or a larger index.
500k sessions ≈ 38 MB (~77 bytes each), asserted ≤ 45 MB. A per-NAS doubly linked list (prev/next columns)
supports Accounting-On/Off.

**Rules** (`AccountingStateMachine`, cluster time only):

| Event | Rule |
|---|---|
| Start | same start key as stored → DUPLICATE; a **late Start** (below) → MERGED for an active session, STALE for a stopped one; otherwise a new session instance → APPLIED |
| Interim | progress (session time, then event timestamp, then total octets) equal → DUPLICATE, older → STALE, newer → APPLIED; unknown session → created implicitly; after Stop → STALE |
| Stop | already stopped → DUPLICATE; else APPLIED + tombstone (1 h); never rejected for capacity |
| Accounting-On/Off | exact-key window (15 min); when APPLIED, every active session of the NAS stops |
| other status types | exact-key window |

A progress value the incoming event carries but the stored one lacks counts as 0 on the stored side (a
Start has no session time, so the first Interim is progress) — found by the local smoke test.

**Out-of-order Start** (state version 3, 2026-11-08). A lost or delayed Start must neither lose the session nor
reset it. An Interim or Stop for an unknown session creates it. A Start with a new start key for an existing session
is *late* when it is not newer than the session's last event (both carry an Event-Timestamp), or — without
timestamps — when the session is active and never saw a Start. A late Start is acknowledged like any committed event
(the gateway sees APPLIED) but only records its start key (its retransmissions are duplicates) and the
last-seen time; progress, counters and status stay as the Interim left them. For a stopped session it is STALE and
does not reopen it. A Start newer than the session's last event is still a new instance of the session id (NAS
rebooted without Accounting-On). Without Event-Timestamps a Start for a *stopped* session cannot be told from a new
instance and starts it over, as before. MERGED counts as applied and changes the digest.

**Housekeeping** every 60 s (cluster timer): expired tombstones, idle sessions (no event for 2 h) and expired
exact keys are removed, iterating slots in order. **Capacity**: new sessions beyond `maxSessions` are
rejected (no ACK). **eventId** = log position. **State digest** = running hash over applied changes and
sweeps; equal on every replica. **Snapshots** stream sessions in chunks of 256 plus the exact keys;
counts are verified on load.

## Consequences
- Deterministic by construction; proven by a replay test, a jqwik property (duplicates never change the
  result) and digest comparison across members in every integration and e2e test.
- A delayed Start never moves a session back; a jqwik property moves Starts behind their session's later events and
  checks every session ends as with in-order delivery.
- Out-of-order delivery after a failover legitimately turns an older Interim into STALE: its progress is
  already reflected by the newer one.
