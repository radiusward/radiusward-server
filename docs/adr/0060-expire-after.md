# ADR 0060: Expire-After the first login

Status: Accepted (2026-11-10). Phase 5, work package 5.36 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)). Extends
[ADR 0049](0049-time-and-usage-limits.md).

## Context
Prepaid vouchers and guest accounts run for a time from their first use ("24 hours from activation"), not from a
fixed date. `Expiration` needs the date in advance.

## Decision
- **`Expire-After := <seconds>`** (check item of the user or a matching group): the account ends that long after its
  first login. The first login is the start of the user's first exported session in `accounting_session`
  (`auth.counter.first.query` to use another source); with none yet, now.
- After it: rejected. Before it: the Session-Timeout is cut to the time left, like the other limits.
- It uses the counters' connection, `auth.counter.sql.url`, which now works without any `auth.counters`. Without it a
  user with `Expire-After` is rejected (and it is logged once); an unreachable database leaves requests unanswered.

## Consequences
- The clock starts at the first Accounting-Start that reaches PostgreSQL, not at the first Accept: a user accepted
  but never online keeps the full time.
