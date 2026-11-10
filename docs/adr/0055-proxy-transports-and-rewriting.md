# ADR 0055: Proxying over TCP and DTLS, rewriting, inner proxying over RadSec

Status: Accepted (2026-11-10). Phase 5, work package 5.31 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)). Extends
[ADR 0037](0037-proxying.md) and [ADR 0044](0044-inner-tunnel-proxying.md).

## Context
Home servers were reached over UDP or RadSec (TLS). radiusward accepts RADIUS over plain TCP (RFC 6613,
[ADR 0045](0045-radius-over-tcp.md)) and DTLS (RFC 7360, [ADR 0038](0038-dtls.md)) but could not send
it. Roaming federations and partners also ask for requests to be adjusted on the way (an Operator-Name added,
internal attributes removed) and for answers to be filtered. The inner proxy reached UDP home servers only.

## Decision
- **`home.<id>.transport`**: `udp`, `tls`, **`tcp`** (port 1812, a secret required) or **`dtls`** (port 2083, secret
  `radius/dtls` by default, `tls.ca` required, our certificate as for TLS). Each is a non-blocking connection on the
  proxy's selector (`HomeConnection`: `TlsClient`, `HomeTcpClient`, `HomeDtlsClient`):
  - TCP like TLS: one connection, a request written once and waiting as long as all UDP tries would (RFC 6613 §2.6.1);
  - DTLS like UDP: records can be lost, so requests are sent again every `proxy.timeout`; handshake flights are
    retransmitted on a doubling timer, a handshake not finished in 15 s is given up; packets written during the
    handshake wait for it.
  Status-Server probes, dead detection and failover work the same over every transport. CoA from home servers stays
  UDP-only.
- **Rewriting per realm**, resolved and encoded once with the gateway's dictionary when the proxy starts:
  - `realm.<id>.pre-proxy.remove`: standard attributes left out of the request;
  - `realm.<id>.pre-proxy.add`: items (`Operator-Name = "1example.net", Cisco-AVPair += "x=y"`) appended to it;
  - `realm.<id>.post-proxy.remove`: standard attributes left out of the answer to the NAS.
  Attributes the proxy manages (User-Name, User-Password, CHAP-Password, CHAP-Challenge, Proxy-State, EAP-Message,
  Message-Authenticator) cannot be removed. The packet path tests a type table and copies bytes: no allocation.
- **Inner proxying** ([ADR 0044](0044-inner-tunnel-proxying.md)) also uses `tls` and `tcp` home servers: a blocking
  connection per inner request on the access worker (TLS sessions resumed from the context's cache). `dtls` home
  servers are skipped for inner requests.

## Consequences
- Proxy chains across transports are possible: UDP from the NAS, DTLS to a partner, TLS to a federation.
- A rewrite error (unknown attribute, value that does not encode) stops the gateway at start.
- Inner requests over TLS cost a handshake (or a resumption) each; volumes are small (one per tunnel).
