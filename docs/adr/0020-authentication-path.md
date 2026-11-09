# ADR 0020: The Access-Request path on the gateway

Status: Accepted (2026-11-09). Phase 5, work package 5.2 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Access-Requests must be answered within the NAS timeout (typically 3–5 s, retried a few times), deciding them may
need an identity store that can be slow or unavailable, and a mass reconnect sends thousands per second. The
accounting path (ADR 0006, ADR 0011) is a non-blocking NIO agent that never waits; authentication must keep that
property while some decisions wait for I/O.

## Decision
- **`AuthAgent`**: a second non-blocking NIO `DatagramChannel` (port 1812, `gateway.auth.port`) owned by one agent
  thread — beside `UdpAgent` on the shared thread, or its own with `gateway.threading=dedicated`. It validates the
  packet, finds the NAS entry, checks Message-Authenticator, answers retransmissions from the reply cache and hands
  the request on; it sends the replies from the same socket. It never blocks.
- **Message-Authenticator** on Access-Requests is required by default (`nas.<name>.access.message-authenticator`,
  BlastRADIUS / CVE-2024-3596) and always with EAP (RFC 3579 §3.2). Every reply carries it as the first attribute
  (`AccessResponses`).
- **Workers**: `gateway.auth.workers` threads (default 4) decide requests through an `AccessHandler` (identity
  stores and policy, 5.3/5.4) and build the signed reply. They may wait for a store within its timeouts; the socket
  thread does not.
- **Bounded hand-off**: a fixed table of `gateway.auth.pending` slots (default 256) holds request and reply bytes;
  lock-free queues (`ManyToManyConcurrentArrayQueue` to the workers, `ManyToOneConcurrentArrayQueue` back) carry
  pre-boxed slot ids. No free slot or a full queue → the request is dropped (counter `busy`) and the NAS retransmits.
- **Reply cache** (RFC 5080 §2.2.2): key = source address, port, Identifier, Request Authenticator; a request being
  decided is marked in flight, so retransmissions are dropped instead of decided twice; the reply bytes (≤ 1 KiB)
  are kept for `gateway.auth.reply.cache.ttl` (10 s) in a fixed ring of `gateway.auth.reply.cache.entries` (4096).
  A request answered with nothing (store down, handler error) is decided again on its retransmission.

## Consequences
- The socket thread allocates nothing per request (the JDK's sender address aside), proven by
  `GatewayAllocationIT`; a slow store costs worker time and, when all slots are busy, drops — never a growing queue.
- Memory is fixed: about 2 × 4 KiB per slot plus 1 KiB per cache entry (≈ 6 MiB with the defaults).
- Conversations that span several requests (EAP) keep their own state in the EAP layer (5.7); the reply cache only
  covers retransmissions of one request.
