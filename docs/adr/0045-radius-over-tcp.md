# ADR 0045: RADIUS over plain TCP

Status: Accepted (2026-11-10). Phase 5, work package 5.21 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
RFC 6613 defines RADIUS over TCP: RadSec's framing (packets back to back, delimited by their length field) without
TLS. Some NAS and proxies use it inside protected networks to avoid UDP fragmentation and lost datagrams. Other
servers accept it. RadSec (ADR 0034) already has everything except the missing TLS.

## Decision
- **Two listeners in the RadSec agent**: `radius.tcp.auth.port` (1812/tcp) and `radius.tcp.acct.port` (1813/tcp)
  when `radius.tcp.enabled`, on the same selector, sharing `radsec.connections` and the timeouts.
  - Neither needs a certificate: plain TCP can run without RadSec or DTLS.
  - Connections have no `SSLEngine`; bytes are read into the packet buffer and written as they are.
- **Which NAS**: when a connection is accepted, it belongs to the NAS entry of its source address, which must allow
  TCP (`nas.<name>.tcp = true`); otherwise it is closed at once. There is no certificate to identify an entry by.
- **Secret**: the entry's own secret, as over UDP (RFC 6613 §2.2). The link holds the TCP entries after the RadSec
  and DTLS ones, with the entry's id, so events dedup across all four transports.
- **Ports keep their kind** (RFC 6613 §2.3):
  - an Accounting-Request on the authentication port, or an Access-Request on the accounting port, is discarded and
    counted;
  - Status-Server goes to the agent of its port.
  - A malformed length closes the connection, as over RadSec.
- **CoA**: not over plain TCP connections; a NAS on TCP gets CoA over UDP (or its RadSec connection or DTLS
  association).
- **Metrics**: `radiusward_gateway_tcp_total{result}`.
- **Use**: only inside protected networks. Without TLS, user names and accounting cross the network readable, as over
  UDP. RadSec is the default recommendation.

## Tests
- `RadiusTcpIT`, through a gateway without certificates:
  - Access-Requests and Status-Server on the authentication port with the NAS's secret;
  - an Accounting-Request there discarded;
  - an entry without `tcp` refused at connect;
  - a malformed length closing the connection.
- `RadsecAccountingIT`, with 3 cluster members: an Interim over plain TCP in the same session as a Start over DTLS
  and an Interim over RadSec.
- `RadsecproxyIT#papOverPlainTcp`: `radclient -P tcp` to the gateway's TCP port, accept and reject.
- `RadsecConfigTest`: plain TCP without certificates, beside RadSec, and a missing `nas.<name>.tcp`.
