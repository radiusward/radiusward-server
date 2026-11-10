# ADR 0058: Authentication log

Status: Accepted (2026-11-10). Phase 5, work package 5.34 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Help desks and audits ask "when did this user last log in, and why was it refused?". Traces
([ADR 0052](0052-request-traces.md)) cover chosen users for a while; counters have no names. Other servers log every
decision (`radpostauth`, auth log files).

## Decision
- **`auth.log.dir`**: daily JSON-lines files `auth-YYYY-MM-DD.jsonl` (UTC days), one line per decision:
  `time`, `nas` (entry), `user` (User-Name), `station` (Calling-Station-Id), `result` (`accept`/`reject`) and for a
  reject its `reason` — the first cause the handler recorded (e.g. `user not in any store`, `outside Login-Time`,
  `usage limit reached`), else `credentials or method rejected`.
- **`auth.log.sql.url`** (+ `.user`, `.password`, `.table`, default `auth_log`): the same into PostgreSQL; the
  gateway creates the table if missing (`id, authdate, nas, username, calling_station_id, reply, reason`).
- Both may be set. Workers only offer entries to a bounded queue (`auth.log.queue`, 10 000); a thread of its own
  writes batches. A full queue, a failing disk or database drops entries and counts them
  (`radiusward_gateway_auth_log_entries_total{result}`), never slows a decision.
- Accepts and rejects decided by this gateway are logged; challenges (EAP rounds) and unanswered requests are not,
  and proxied requests are logged by their home server. Passwords are never written.

## Consequences
- Rotation is by day; retention is the operator's (a cron job or a partition drop).
- The log is per gateway; entries of all gateways meet in the shared table.
- Not reloadable: it starts with the gateway.
