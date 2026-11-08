# ADR 0011: Gateway pipeline — ring buffers, stateless response cache, resubmission

Status: Accepted (2026-11-08). Refines ADR 0006. Amended in Phase 2: resubmit on a new leader.

## Context
The gateway must never block, never allocate per packet, keep working through leader elections and answer
retransmits quickly.

## Decision
- **Two agents** (`UdpAgent`, `ClusterClientAgent`) on one thread (small profile) or two, connected by two
  Agrona `OneToOneRingBuffer`s carrying SBE bytes — zero-copy and allocation-free. The LMAX Disruptor is not
  used here; it is used only inside Log4j2 (ADR 0013).
- **Response cache** (RFC 5080) keyed by source address, port, Identifier and Request Authenticator stores
  only a state: `PENDING` (with the correlation id) or `COMMITTED`. The Accounting-Response is deterministic,
  so a COMMITTED retransmit is answered by re-encoding it from the incoming packet (~32 bytes per entry).
- **Pending slab**: preallocated slots hold what the response needs (sender, Identifier, Request
  Authenticator, Proxy-State, Message-Authenticator flag); correlation id = slot + generation.
- **Resubmission**: a retransmit of a request pending longer than `gateway.retransmit.resubmit.after`
  (default 1 s) is submitted again. Commands offered to a leader that died before committing are lost;
  without this the gateway would swallow every retransmit until its pending timeout — found by the
  failover demo (846 of 7,000 events failed before, 0 after). Safe because the cluster deduplicates.
- **Resubmission on a new leader** (Phase 2): the pending slab also keeps the encoded command (1 KiB per
  slot). When the cluster client sees a new leader (`onNewLeader`, or a reconnect), it tells the UdpAgent,
  which resubmits every pending command at once instead of waiting for the NAS to retransmit. Together with
  a 1.5 s leader heartbeat timeout and 0.5 s election timeout, a crashed leader is replaced before a typical
  3 s NAS timeout, so the NAS never notices.
- **Cluster client** keeps polling egress while back-pressured, reconnects asynchronously after a lost
  session, sends keep-alives. Full rings or tables mean "drop", never "block".
- Known JDK limitation: `DatagramChannel.receive` allocates a sender address when the sender changes (~80
  bytes, ~1.3 MB/s at peak with 1,000 NAS); radiusward's own code allocates nothing (`GatewayAllocationIT`).

## Consequences
- Failover with `kill -9` of the leader under load: every event acknowledged within the NAS retry window
  (Phase 1: ~6 s outage with a 3 s leader heartbeat timeout).
- Phase 2, same test at ~2k requests/s: **0 retransmissions**, worst ACK latency 2.2–2.3 s (detection 1.5 s,
  election ~0.6 s, redirect ~0.1 s), each gateway resubmitting ~2,200 pending commands — locally, in the e2e
  test and in containers (`FailoverTimingIT`, `PartitionIT`).
- Memory: 1 KiB × `gateway.pending.capacity` for stored commands (small: 16 MiB).
- Late commits for released slots are counted and ignored.
