# ADR 0006: Plain NIO DatagramChannel, no Netty

Status: Accepted (2026-11-07); pipeline details in [ADR 0011](0011-gateway-pipeline.md)

## Context
The gateway needs UDP at ~16k packets/s peak, small memory, and a threading model that fits Aeron's
agents.

## Decision
Use the JDK's non-blocking `DatagramChannel`, owned by one Agrona agent that both receives and sends
(replies leave from the socket the NAS sent to). Preallocated direct buffers, `UnsafeBuffer`
flyweights, no allocation per packet. Scale with `SO_REUSEPORT` and several agents, or more pods. The
transport sits behind a `RadiusTransport` interface; Netty may be reconsidered only for RadSec
(RADIUS over TLS, RFC 6614). The Maven enforcer bans `io.netty`.

## Consequences
- No extra dependency or native artifacts; same model as the Aeron media driver.
- One syscall per datagram (no `recvmmsg`) — irrelevant at this load (Phase 0 codec: ~2.2 M packets/s
  per core).
- TLS transports will need a separate decision.
