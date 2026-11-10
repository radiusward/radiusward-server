# ADR 0043: CoA relay from home servers

Status: Accepted (2026-11-10). Phase 5, work package 5.19 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
With proxying (ADR 0037), the home server of a realm authenticates the realm's users, but the NAS talks only to us.
When that home server wants to end or change a session (an account blocked, a quota used up), it sends CoA or a
Disconnect-Request to the proxy, which must forward it to the NAS (RFC 5176 §3.1). Federations and wholesale access
depend on this. Work package 5.13 left it out.

## Decision
- **Who may send**: home servers with `home.<id>.coa = true`, over UDP. The listener (`proxy.coa.port`, 3799, on
  `gateway.listen.host`) starts only when such a home server exists, and needs `coa.enabled`, because the relay uses
  the gateway's own CoA path.
  - A request must come from the home server's address and carry a valid Request Authenticator for its secret, and a
    valid Message-Authenticator if it has one. Anything else is dropped and counted.
  - RadSec home servers are not covered: their CoA would come over our client connection to them.
- **Which NAS**: the request names the session the way the home server knows it from the accounting it received.
  - The user's active sessions in the replicated state (ADR 0036) are looked up by User-Name, and the one with the
    request's Acct-Session-Id is taken, if it has one.
  - Without a user, the NAS entry of the request's NAS-IP-Address is used (single-address entries only).
- **What is sent**: the home server's attributes as they came, without its Proxy-State and Message-Authenticator. It
  is signed for the NAS (its CoA secret, Message-Authenticator always), over the NAS's RadSec connection, DTLS
  association or UDP target, as for our own CoA.
- **The answer**: the NAS's ACK or NAK, with its Error-Cause, goes back to the home server with the home server's
  Proxy-State, signed with its secret.
  - No session or NAS: NAK with Error-Cause 503 (Session Context Not Found).
  - No answer from the NAS: NAK with 506 (Resources Unavailable).
  - A retransmission (same address, identifier and authenticator) gets the same answer within 30 s, or nothing while
    the request is under way, and is not sent to the NAS twice.
- **Threading**: the relay has its own thread, because finding a session asks the cluster and may wait up to 5 s.
  The RADIUS agents never block.
- **Metrics**: `radiusward_gateway_coa_relay_total{result}`: received, unknown_sender, bad_authenticator, malformed,
  duplicate, ack, nak, no_session, no_answer.

## Tests
- `CoaIT#aHomeServerDisconnectsItsUserThroughTheRelay`, with 3 cluster members and a fake NAS:
  - a home server's Disconnect-Request reaches the NAS signed for it, without the home server's Proxy-State;
  - the ACK returns with that Proxy-State, signed with the home secret;
  - a retransmission is answered again without a second request;
  - an unknown session gets a NAK with Error-Cause 503;
  - a request signed with another secret is dropped and counted.
- `ProxyConfigTest`: `home.<id>.coa`, `proxy.coa.port`, and RadSec home servers refused.
