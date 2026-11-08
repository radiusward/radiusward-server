# ADR 0001: Aeron Cluster for replication and consensus

Status: Accepted (2026-11-07)

## Context
Accounting records must survive the loss of a node, and every acknowledged record must be recoverable.
That needs a replicated, ordered, durable log plus leader election. Aeron Transport alone only moves
messages; building consensus on top of it would mean re-implementing Raft.

## Decision
Use **Aeron Cluster** (Raft log, Archive persistence, leader election, deterministic service container)
with **three nodes and static membership**. "Delivered to two instances" is defined as *majority commit:
leader plus one follower*. Horizontal scaling beyond one cluster is done later by sharding (by NAS or
session key), not by adding replicas.

## Consequences
- Survives one node down; two nodes down stops acknowledgments (no majority).
- The clustered service must be deterministic (ADR 0005).
- Membership changes need a runbook (replace member, ClusterBackup); hot standby is an Aeron Premium
  feature and not used.
- One leader processes all commands: ~16k req/s peak is far below Aeron Cluster limits.
