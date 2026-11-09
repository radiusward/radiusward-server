# ADR 0034: RadSec (RADIUS over TLS)

Status: Accepted (2026-11-09). Phase 5, work package 5.9 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
RADIUS over UDP protects only passwords and keys, with MD5 and a shared secret. Everything else crosses the network
readable: user names, MAC addresses, accounting. NAS in other networks (branch offices, cloud Wi-Fi controllers,
roaming federations) are often reached over the internet. RadSec (RFC 6614, with RFC 6613 for RADIUS over TCP) runs
RADIUS inside mutually authenticated TLS over TCP, port 2083, carrying authentication and accounting on one
connection.

ADR 0006 chose plain NIO for UDP and named RadSec as the place to reconsider Netty. The gateway's two socket agents
already decide every packet without blocking. What RadSec adds is a TLS transport in front of them.

## Decision
- **Transport**: `RadsecAgent`, one thread (or part of the shared socket thread), with a non-blocking NIO selector
  and the JDK's `SSLEngine` per connection. There is no Netty: TLS records and RADIUS framing (the packet's length
  field) are simple enough over `SSLEngine`.
  - TLS 1.2 and 1.3 (`radsec.versions`), client certificates required.
  - The server's certificate, key, client CAs, CRL/OCSP revocation and reload work as for EAP (ADR 0033), under
    `radsec.*`.
- **Which NAS**: after the handshake the connection belongs to the NAS entry of its source address, like a
  datagram.
  - The entry must allow RadSec (`nas.<name>.radsec = true`).
  - If `nas.<name>.radsec.identity` is set, the client certificate must carry that name (common name, DNS, e-mail
    or UPN).
  - Otherwise the connection is closed.
  - The entry's RadSec secret is `radsec` (RFC 6614 §2.3) unless `nas.<name>.radsec.secret` says otherwise. Its id,
    vendor, identity attribute and Message-Authenticator policy are the entry's. An event therefore has the same
    keys whether it arrives over UDP or RadSec, and the cluster deduplicates it across both.
- **Same decision path**: every packet read from a connection goes through a ring (`RadsecLink`) to the agent that
  handles it over UDP.
  - Access-Requests go to the `AuthAgent`, and on to the workers.
  - Accounting-Requests go to the `UdpAgent`, and on to the cluster, answered only after the commit.
  - Status-Server goes to the first of them.
  - Each request carries a route: the connection index and its generation. Replies come back through a second ring
    with that route. A reply for a connection that has closed in the meantime is dropped, never written to the next
    connection in its place.
  - The response caches are keyed by the route instead of the address, so a resend on another connection is decided
    again; RFC 6613 does not allow resending on the same one.
  - No objects are allocated per packet on these paths; the TLS engine itself allocates.
- **Never blocking**:
  - A full ring drops the packet; the NAS times out and retries.
  - A peer that does not read its replies, over 1 MiB of pending output, is disconnected.
  - A malformed packet (length below 20 or above 4096) closes the connection (RFC 6613 §2.6.4).
  - Packet types the gateway does not answer, such as CoA, are counted and ignored.
  - Limits: `radsec.connections` (default 256), `radsec.handshake.timeout` (10 s), `radsec.idle.timeout` (off; TCP
    keep-alive is on).
- **Metrics**: `radiusward_gateway_radsec_total{result}`, `radiusward_gateway_radsec_connections`,
  `radiusward_gateway_radsec_tls_reloads_total`.
- **Interop**: `RadsecproxyIT` runs radsecproxy 1.11 (`testing/radsec-client`) as the RadSec client. FreeRADIUS's
  `radclient` and wpa_supplicant's `eapol_test` speak UDP to it: PAP, PEAP and TTLS. The MS-MPPE keys are encrypted
  with the RadSec secret, re-encrypted by radsecproxy, and must still match the peer's MSK.

## Consequences
- NAS can reach gateways across untrusted networks without a VPN. Their identity is a certificate, not only an
  address and a secret.
- The gateway's UDP behaviour is unchanged: RadSec is off unless `radsec.enabled`, and its requests take the same
  decision and commit paths.
- Not covered:
  - DTLS (RFC 7360).
  - Dynamic peer discovery (RFC 7585).
  - Identifying a NAS by certificate alone, regardless of its address.
  - The gateway as a RadSec client (it does not proxy).
