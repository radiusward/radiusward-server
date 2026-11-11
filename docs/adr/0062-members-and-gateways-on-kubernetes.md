# ADR 0062: Members and gateways on Kubernetes

Status: Accepted (2026-11-11). Work package 4.1 of [Phase 4](../plans/phase-4.md); the spike's measurements are below.

## Context
Cluster membership is static: `cluster.members` lists every member's host, and Aeron Cluster uses it for all of a
member's endpoints. The compose stack gives members fixed IP addresses because a lookup of a stopped container's name
once blocked the media driver for seconds (Phase 2). On Kubernetes a pod gets a new IP every time it is recreated,
and NAS devices reach gateways through Services, so the questions were: can members be addressed by name, how fast
does a leader fail over, what does a rolling restart do, can a member with a lost volume rejoin, and what happens
when a whole node dies.

## Spike
kind 0.33 (Kubernetes 1.37) with three workers, the `small` image, members as a StatefulSet with a headless Service
(`publishNotReadyAddresses: true`), anti-affinity, a 2 Gi volume each; gateways in the cluster network; `radclient
load` from a pod (500 sessions, 200 requests/s, NAS timeout 3 s, 3 retries).

| Experiment | Result |
|---|---|
| Cold start, members by DNS name (`radiusward-node-0.radiusward-node`) | leader after 16 s, no restarts |
| Leader pod deleted (graceful), heartbeat timeout 2.5 s | 3500/3500 acknowledged, 25 retransmissions, max 3.3 s; the new pod rejoined with a new IP |
| Leader pod killed (`--grace-period=0`), 2.5 s | 3500/3500, 13 retransmissions, max 3.2 s |
| Leader pod killed, **1.5 s** | 3500/3500, **0 retransmissions**, max 2.3 s |
| Leader pod deleted (graceful), 1.5 s | 3500/3500, 0 retransmissions, max 2.2 s |
| Rolling restart of all members, readiness = "leader known" | **932/6500 failed**: the next member restarted 6 s after the previous one, before it had caught up; the remaining two needed 41 election rounds (23 s) |
| Rolling restart with 30 s between members | 9500/9500, 0 retransmissions, max 2.3 s |
| Member volume deleted after the log was purged | the empty member loops on "failed to join catchup log" and never becomes ready |
| Node with the leader and the only gateway stopped | 3965/5000 failed: one gateway is a single point of failure |
| Node with the leader and one of two gateways stopped, one shared Service | 496/6500 failed: the Service sent part of the traffic to the dead gateway until the node was NotReady (48 s) |
| Node with a gateway stopped, **one Service per gateway**, the NAS retrying the other | 6500/6500, max 3.0 s |
| Node back after a stop | its member restarted with a new IP before its own DNS record existed, crashed on resolving its own name and recovered only after 5 restarts (back-off) |

## Decision
1. **Members are addressed by their StatefulSet DNS names**; Aeron re-resolves them when a pod returns with a new
   IP. The headless Service publishes not-ready addresses, so members find each other before any is ready.
2. **Leader heartbeat timeout 1.5 s on Kubernetes too**, not the 2.5 s planned in Phase 2: in the spike 1.5 s
   replaced a dead leader without a single NAS retransmission and 2.5 s did not. Members get guaranteed CPU
   (requests = limits) so throttling does not look like a dead leader; load tests (4.9) watch for spurious
   elections.
3. **Readiness of a member means caught up**: `/ready` reports a member as not ready until it has a leader and its
   applied position has reached the leader's commit position, so a rolling update waits for it (code in 4.2).
   Until then the chart sets `minReadySeconds`.
4. **A member waits for its own name** to resolve to its own address before it starts Aeron (bounded, logged),
   instead of crashing into back-off (code in 4.2).
5. **A member with a lost volume is seeded** from a backup of the cluster (Aeron `ClusterBackup`: the latest
   snapshot and the log after it) before it starts; an empty member cannot catch up once the log is purged (4.6).
6. **Gateways are a StatefulSet** without volumes: `gateway.id` comes from the pod index like `cluster.node.id`,
   at least two, spread over nodes.
7. **Every gateway gets its own address** (one Service per gateway pod) and NAS devices are configured with two
   gateways as primary and secondary RADIUS servers; retries through the other gateway are deduplicated by the
   cluster. A single shared Service stays available for small setups, documented as losing up to the node-failure
   detection time (about 40–50 s) for the NAS devices behind a failed node.

## Consequences
- The Helm chart (4.2, 4.3) follows these decisions; `cluster.leader.heartbeat.timeout` keeps one default.
- Phase 2's planned 2.5 s for Kubernetes is withdrawn.
- Member replacement depends on the backup (4.6); until then the runbook is to restore the whole cluster from a
  snapshot.
