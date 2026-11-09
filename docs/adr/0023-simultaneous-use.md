# ADR 0023: Simultaneous use through the cluster

Status: Accepted (2026-11-09). Phase 5, work package 5.5 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)). First
rule change behind the state-version gate (ADR 0005): state version 6.

## Context
`Simultaneous-Use := N` limits how many devices a user may have online. Only the cluster sees every active session
across all gateways. Counting from accounting alone leaves a gap: between an Access-Accept and the device's
Accounting-Start the new session is invisible, so two logins at the same moment, on different gateways, would both
get the last place. Sessions whose Stop was lost keep counting until they time out, and a device that reconnects
before its old session closed must not lock itself out.

## Decision
- **Keys**: gateways put a `userKey` (64-bit hash of the User-Name, ASCII case folded) and a `deviceKey` (the
  Calling-Station-Id: a MAC address in any notation as its 48 bits, anything else hashed) into every
  `AccountingCommand`; the access path computes the same keys (`UserKeys`).
- **Counting** (state version 6): an applied event records the user and device of its session. The session store
  counts, per user, the **distinct devices** online; several sessions of one device count once, every session without
  a device counts on its own. The counts follow every state change (Start, Stop, Accounting-On/Off, idle timeout) and
  are rebuilt from the sessions when a snapshot is loaded. A session that predates version 6 gets its user with its
  next event.
- **Reservations**: after the credentials are verified, a user with a limit is checked through the log: the worker
  sends `AuthReservation` (user, device, limit, TTL) and waits for `AuthReservationResult`, which the cluster sends
  after the commit — the same boundary as Accounting-Responses. The state machine grants when the device is already
  online or holds a reservation (a reconnect or retransmission: extended, never counted twice), or when devices online
  plus other live reservations stay below the limit; a grant records a reservation until `now + TTL`. The device's
  Accounting-Start ends it (by device, else one made without a device, else the one expiring first); otherwise it
  expires and the sweep removes it. The TTL travels in the log entry, so every member computes the same expiry;
  `service.auth.reservations.max` bounds the table (full → no answer).
- **Answers**: granted → Accept; denied → Reject; cluster unreachable, no answer within
  `gateway.auth.reservation.timeout` or the table full → no answer (the NAS retries). Users without a limit never
  reach the cluster.
- **Upgrades**: before every member runs version 6 and it is activated, the cluster answers `UNSUPPORTED` and the
  gateway ignores the limit (logged once) — as before 5.5. Older code ignores the new message and the new fields, and
  never sees a reservation in a snapshot (they exist only once version 6 is active).
- **Gateway path**: workers write reservations into a many-to-one ring that the cluster client agent forwards; the
  answer comes back through a mailbox per worker. A worker waits for it (spinning briefly, then parking), like it
  waits for an identity store.

## Consequences
- A limit holds across gateways and at the same moment; a reconnecting device is always let in again.
- Sessions with a lost Stop count until the idle timeout of their NAS entry (`nas.<name>.idle.timeout`); asking the
  NAS directly would come with CoA/Disconnect.
- Users are matched by name only: an accounting User-Name that differs from the authenticated one (realm rewriting,
  EAP outer identities) is not recognised; a signed Class token would solve it later.
- Every session carries 16 more bytes (~+32 MB at 2M sessions, ADR 0004); a reservation costs ~40 bytes.
- During a rolling upgrade, while the leader still runs older code, limited users get no answer (the old leader
  ignores the request); after the upgrade, until version 6 is active, their limit is not applied.
