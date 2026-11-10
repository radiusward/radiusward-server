# ADR 0052: Per-request debug traces

Status: Accepted (2026-11-10). Phase 5, work package 5.28 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
"Why was this user rejected?" was answered by counters and once-per-cause warnings, never per request: per-packet log
lines are forbidden on the packet path, and a log level for everything would flood the log of a busy gateway. Other
servers offer a debug mode for one user or NAS. Operators need the same without a restart.

## Decision
- **Conditions** select Access-Requests: a user name, a NAS entry or a Calling-Station-Id (compared without
  separators and case). Configured ones (`trace.users`, `trace.nas`, `trace.stations`) stay; temporary ones come from
  `POST /trace?user=…|nas=…|station=…&for=10m` on the management port (`trace.api.token`, at most 24 h, default
  15 min); `GET /trace` lists them, `DELETE /trace` drops the temporary ones.
- A matching request is logged once, when decided, to the logger `io.radiusward.trace` (INFO whatever
  `radiusward.log.level` is): its attributes by name, the steps the handler took (store, groups that apply or not,
  Auth-Type, Simultaneous-Use, Expiration, Login-Time, counters, the Session-Timeout cap, pools, rules) and the
  reply's attributes; a reject without a recorded cause says "credentials or method rejected".
- **Secrets are never written**: passwords, CHAP and MS-CHAP values, EAP payloads, MPPE and other keys, the
  Message-Authenticator and every attribute the dictionary encrypts appear as their length.
- Tracing happens on the access workers. Without conditions a request costs one volatile read; Accounting-Requests
  and the packet path are not traced.

## Consequences
- A trace shows the outer request; EAP conversations produce one trace per round.
- The token protects the API like the CoA API's ([ADR 0036](0036-coa-and-session-identity.md)); without it only configured
  conditions exist.
- Accounting is followed with `radclient decode` and `admin state` instead.
