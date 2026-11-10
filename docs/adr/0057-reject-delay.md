# ADR 0057: Delayed Access-Rejects

Status: Accepted (2026-11-10). Phase 5, work package 5.33 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
A NAS, or an attacker behind one, can try passwords as fast as rejects come back. Other servers hold rejects back
for about a second (`reject_delay`). A worker that sleeps would tie up the pool and let a flood of wrong passwords
starve everyone.

## Decision
- **`auth.reject.delay`** (default `1s`, at most `5s`, `0s` off): an Access-Reject decided by this gateway is held
  by the auth agent, not the worker. Its slot goes into a FIFO with its due time (the delay is the same for all, so
  the queue is ordered) and the reply is sent when due; the agent checks the queue on every turn. Nothing is
  allocated: two preallocated arrays of the slots' size.
- During the delay the request stays in flight: retransmissions are dropped as for any request being decided, and
  answered from the reply cache afterwards.
- Accepts, challenges and Status-Server answers are never delayed; neither are rejects from home servers (the home
  server applies its own delay). Reload changes the delay.
- `radiusward_gateway_access_requests_total{result="rejects_delayed"}` counts them.

## Consequences
- A held reject keeps its slot: a flood of wrong passwords fills `gateway.auth.pending` and further requests are
  dropped (`busy`), which is the intended back-pressure; accepts of other users still pass as slots free up.
- NAS timeouts must exceed the delay (they normally do: 3–5 s).
