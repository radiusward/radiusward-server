# ADR 0050: IPv4 address pools

Status: Accepted (2026-11-10). Phase 5, work package 5.26 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
A `Framed-IP-Address` could only come from a user's reply items. BNGs, PPPoE and VPN concentrators that leave address
assignment to RADIUS need pools: an address per session, free again when the session ends, the same one for a device
that reconnects. Other servers keep pools in SQL and free addresses on the Accounting-Stop they receive. In radiusward
accounting goes to the cluster and reaches PostgreSQL through the exporter, and sinks carry no RADIUS logic.

## Decision
- **Pools in PostgreSQL** (`auth.pools`, `auth.pool.<name>.range`: ranges, CIDRs without network and broadcast, single
  addresses; at most 65 536 per pool). The gateway creates `ip_pool (pool, address, device, user_name, expires_at)`
  if missing and adds the addresses; existing rows and leases stay, so gateways share one table.
- **`Pool-Name := <pool>`** (check item of the user or a matching group) asks for an address, unless the reply already
  has a `Framed-IP-Address`.
- **One statement allocates** (`FOR UPDATE SKIP LOCKED`, so concurrent workers and gateways never hand out an address
  twice): an address is free when
  - its **lease** ran out (`auth.pool.<name>.lease`, default 5 min: the time until the session's Accounting-Start is
    exported), and
  - **no open session** in the exported `accounting_session` uses it (`framed_ip`, `stopped_at IS NULL`) — release
    follows accounting without the sink knowing about pools.
  The device (Calling-Station-Id, else the user name) gets its previous address first, also while its own session is
  open (a reconnect before the Stop).
- `auth.pool.sessions = false` relies on the lease alone (no PostgreSQL sink): the lease must then outlast sessions.
- An **empty pool** rejects, or accepts without an address (`auth.pool.<name>.exhausted = accept`); an **unreachable
  database** leaves the request unanswered, like an unavailable store.

## Consequences
- An address returns to the pool once the Stop is exported (plus the lease, if the session was short); sessions closed
  by the cluster's timeout free theirs the same way.
- Only IPv4. `Framed-IPv6-Prefix` and delegated prefixes would need a pool of prefixes; not planned yet.
- Under heavy contention `SKIP LOCKED` may pass over addresses being allocated; a pool close to full can then answer
  "empty" a little early.
