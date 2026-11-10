# ADR 0012: SessionStore and the deduplication algorithm

Status: Accepted (2026-11-08). Details for ADR 0003.

## Decision
**Storage.** Sessions are columns of primitive arrays in chunks of 16,384 slots (4 long, 8 int, 3 byte, 1 char
columns = 69 bytes) plus an open-addressing `int[]` index on the 128-bit session key (linear probing,
backward-shift delete). No object per session; allocation only for a new chunk or a larger index.
500k sessions ≈ 38 MB (~77 bytes each), asserted ≤ 45 MB. A per-NAS doubly linked list (prev/next columns)
supports Accounting-On/Off.

**Rules** (`AccountingStateMachine`, cluster time only):

| Event | Rule |
|---|---|
| Start | same start key as stored → DUPLICATE; a **late Start** (below) → MERGED for an active session, STALE for a stopped one; otherwise a new session instance → APPLIED |
| Interim | progress (session time, then event timestamp, then total octets) equal → DUPLICATE, older → STALE, newer → APPLIED; unknown session → created implicitly, unless its Event-Timestamp is older than the tombstone window → STALE; after Stop → STALE |
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

**Interim older than the tombstone window** (state version 4, 2026-11-09). A stopped session is remembered for
`service.tombstone` (1 h); an Interim arriving within that time is STALE. Later, the session is gone and an Interim
for it would recreate an active session — in a sink it would reopen the stopped row with older counters until the
idle timeout closed it again. So an Interim for an unknown session whose Event-Timestamp is older than the cluster
time minus the tombstone window is STALE (acknowledged, kept in the history, no session). Deterministic: cluster
time and log data only. Accepted costs: a genuine session whose Start was lost *and* whose first Interim arrives
more than the window late stays out of the session state (it is in the history); a NAS clock more than the window
behind makes every Start-less session's Interims stale (sessions with a Start are unaffected); without an
Event-Timestamp the Interim creates the session as before. A Stop is not limited: it carries the final values,
writing them again is idempotent, and refusing it could lose a whole delayed session. A recent Interim for a
session removed by the idle timeout (alive all along) brings it back.

**Housekeeping** every 60 s (cluster timer): expired tombstones, idle sessions and expired exact keys are removed,
iterating slots in order. **Idle timeout** (state version 5, 2026-11-09): per session, set by its latest applied event
from `nas.<name>.idle.timeout` (minutes, about 3 interim intervals; the gateway sends it in the command), else
`service.idle.timeout` (2 h). Acct-Interim-Interval itself is in the Access-Accept, which accounting never sees, so
the operator configures it per NAS entry. A removed idle session is exported as stopped at its **last event**, not
at the sweep — a fixed 2 h timeout used to stretch every session with a lost Stop by up to 2 h. **Capacity**: new sessions beyond `maxSessions` are
rejected (no ACK). **eventId** = log position. **State digest** = running hash over applied changes and
sweeps; equal on every replica. **Snapshots** stream sessions in chunks of 256 plus the exact keys;
counts are verified on load.

## Consequences
- Deterministic by construction; proven by a replay test, a jqwik property (duplicates never change the
  result) and digest comparison across members in every integration and e2e test.
- A delayed Start never moves a session back; jqwik properties move Starts behind their session's later events and
  shuffle all events of all sessions, and check every session ends as with in-order delivery (with
  Event-Timestamps; without them a Start after the Stop still restarts the session, see above).
- Out-of-order delivery after a failover legitimately turns an older Interim into STALE: its progress is
  already reflected by the newer one.

**Users and devices** (state version 6, 2026-11-09, ADR 0023): two more columns (user key, device key; +16 bytes per
session) and two Agrona `Long2LongHashMap`s counting, per user, the active sessions of each device and the distinct
devices online. They are only looked up, never iterated, and are rebuilt from the sessions when a snapshot is loaded.
Reservations live beside the store in `Reservations` (columns, a per-user list, a free list); no decision depends on
slot numbers.

**Off-heap records** (state version 7, 2026-11-10, ADR 0036): `OverloadIT` found that a small member no longer held
2M sessions in its 384 MB heap. The per-user maps of version 6 (one entry per distinct user) and the replica's copy
of every column outgrew it. The store now keeps each chunk off-heap, in direct buffers:
- a 72-byte core record (the columns above), for members and the exporter's replica;
- a 32-byte member record (user, device, first event, the user's list), allocated with a chunk's first use;
- the 64-byte identifying attributes, also allocated with a chunk's first use.

The replica never allocates the member record or the identities. The two maps became an `int[]` index by user,
pointing at the head of a list of the user's active sessions linked through the member records. Distinct devices are
counted along that list, at most up to the limit being checked.

The index on the session key stays an `int[]` on the heap. At 2M sessions the state needs ~60 MB of heap and ~460 MB
off-heap for member and replica together (`StateFootprintIT`).

