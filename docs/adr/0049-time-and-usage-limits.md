# ADR 0049: Login times, expiry and usage counters

Status: Accepted (2026-11-10). Phase 5, work package 5.25 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)). Extends
[ADR 0021](0021-identity-stores.md) and [ADR 0022](0022-reply-attributes.md).

## Context
`Expiration` rejected a user after a date, but nothing limited *when* a user may log in or *how much*: hotspots,
prepaid and office networks need login windows, daily or monthly time quotas and data volumes, and a session that
ends when the window, the expiry or the quota does. Other servers do this with `Login-Time` and SQL counters over
their accounting tables. radiusward's accounting is in the cluster and, exported, in PostgreSQL
(`accounting_session`).

## Decision
- **`Login-Time`** (check item, user or matching group): days `Mo`…`Su`, `Wk`, `Al`/`Any`, day ranges (`Mo-Th`), an
  optional `HHMM-HHMM` that may run past midnight; entries separated by `,` or `|`. Outside every window the user is
  rejected; a value that does not parse rejects too (and is logged once).
- **Usage counters** (`auth.counters`): each names a check item holding the user's limit
  (`Max-Daily-Session := 3600`), a kind (`time` or `octets`), a reset (`daily`, `weekly`, `monthly`, `never`) and
  an SQL query (user, period start → number). The defaults read the PostgreSQL sink's `accounting_session`:
  - time counts the part of each session after the period began (`session_seconds` from `started_at`);
  - octets count input + output of sessions seen in the period.
  A user at or over the limit is rejected. A counter that cannot be read leaves the request unanswered (the NAS
  retries or fails over), like an unavailable store.
- **Session-Timeout** of the Accept becomes the smallest of: the user's own, the seconds to `Expiration`, to the end of
  the current `Login-Time` window, the time left on each time counter and to its period's end. An octet counter may
  name a reply attribute (`auth.counter.<n>.reply`) that gets the octets left, e.g. a vendor's volume limit.
- Periods and `Login-Time` use `auth.time.zone` (the system's by default); `Expiration` dates without a zone use it
  too.
- Restrictions are applied after the credentials and `Simultaneous-Use`, on the worker threads: SQL counters may
  block like a store, never the packet path.

## Consequences
- The counters lag by the export interval and the NAS's interim interval: a user can overrun by up to one interim.
  Exact real-time limits would need the cluster's sessions and are not attempted; the Session-Timeout cap is what
  ends a session on time.
- Counters read what the sink wrote; other sinks or schemas need their own `query`.
- Counters of users that are proxied (realms, inner proxy) are the home server's business and are not applied.
