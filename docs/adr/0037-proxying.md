# ADR 0037: Proxying to home servers

Status: Accepted (2026-11-10), being implemented. Phase 5, work package 5.13
([plans/phase-5-auth.md](../plans/phase-5-auth.md)); milestones 1–6 (realms, UDP proxy, health, RadSec client, accounting forwarding, discovery) done.

## Context
Roaming federations (eduroam-style), partners and migrations need users of some realms authenticated by other RADIUS
servers ("home servers"), while the gateway keeps deciding everyone else and keeps all accounting. A proxy must not
weaken what the gateway guarantees: it never blocks, never answers a NAS without the home server's decision, and
never lets one network's secret protect another's data.

## Decision
- **Realms**:
  - The User-Name's realm is the part after `@`, or before `\` (`REALM\user`), compared case-insensitively.
  - `realm.<id>.name` sends it to `realm.<id>.pool`; `*` covers every realm no other entry names.
  - A user without a configured realm, or without any realm, is decided locally.
  - A realm is either local or proxied, never "try local, then forward".
  - `realm.<id>.strip` sends the name without the realm.
- **Home servers and pools**: `home.<id>.address` (port 1812 by default), `home.<id>.secret`.
  - `pool.<id>.servers` lists the home servers in order.
  - `pool.<id>.type = failover` (default) picks the first one alive.
  - `pool.<id>.type = load-balance` spreads by device (Calling-Station-Id, else User-Name), so an EAP conversation
    stays on one server.
- **Proxying Access-Requests** happens on the `AuthAgent`'s thread, beside the worker queue: non-blocking, with a
  preallocated table of requests in flight (`proxy.pending`). Retransmissions from the NAS are dropped while in
  flight, and the answer is cached like a local one. Per request:
  - **New authenticators:** a new random Request Authenticator, and a Message-Authenticator (first) for the home
    server's secret.
  - **Credentials:** User-Password is decrypted with the NAS's secret and encrypted with the home server's. CHAP
    without CHAP-Challenge gets the original authenticator as one.
  - **Proxy-State:** the NAS's Proxy-States are kept, and one of ours is added (gateway token, slot, generation).
  - **EAP and the rest** pass through unchanged: the home server runs the EAP conversation.
- **Answers**:
  - An answer counts only if its Response Authenticator verifies and it carries a valid Message-Authenticator (BlastRADIUS;
    `proxy.require.message-authenticator = false` relaxes the latter).
  - Our Proxy-State is removed.
  - MS-MPPE-Send/Recv-Key and Tunnel-Password are re-encrypted with the NAS's secret and authenticator; the salt is
    kept.
  - The answer is signed for the NAS, Message-Authenticator first.
  - Without an answer, the request is sent again `proxy.retries` times every `proxy.timeout`, then dropped. The NAS
    asks again.
- **Health**: a home server is dead once it has answered nothing for `proxy.dead.after` while requests were waiting.
  - Pools skip dead servers. If every server is dead, the first one is tried anyway.
  - Every home server gets a Status-Server (RFC 5997, with Message-Authenticator) every `proxy.status.interval`. Any
    valid answer makes it alive again.
- **RadSec home servers** (milestone 4, `home.<id>.transport = tls`, port 2083, secret `radsec`):
  - One TLS connection per home server, as a client, non-blocking on the same thread. Our certificate is
    `home.<id>.tls.certificate`/`key`.
  - The server's certificate must chain to `home.<id>.tls.ca` and name `home.<id>.tls.name` (else the configured
    host); SNI is sent for host names.
  - The connection is opened by the first request or probe, and again after a failure. Requests written before the
    handshake finishes wait for it.
  - A request is written once (RFC 6613 §2.6.1: no retransmission on a connection) and waits as long as all tries
    over UDP would.
  - Status-Server goes over the connection as well.
- **Accounting** (milestone 5): the gateway commits it in the cluster as always. A `radius` export sink
  (`sink.<name>.type = radius`, in the members) forwards the events of its `realms` to its `servers`.
  - Each event is resent as an Accounting-Request: its original attributes, Acct-Delay-Time raised by the time
    since the commit, and a new Message-Authenticator for the home server's secret.
  - Requests go out in windows of up to 256 and are resent while unanswered. Servers are tried in order, over UDP
    or RadSec.
  - A batch counts as written only when every request is acknowledged. Otherwise the exporter keeps it and retries,
    so a home-server outage delays forwarding but loses nothing.
  - The sink's lease means one member forwards.
  - After a crash or lease handover, the last batch may be sent again. RADIUS accounting allows that, and home
    servers deduplicate by session and counters.
- **Dynamic discovery** (milestone 6, RFC 7585): a realm with `realm.<id>.discover = true` has no pool. Its RadSec
  home servers come from DNS:
  - the realm's NAPTR records with service `aaa+auth:radius.tls.tcp` and flag `s`, in order and preference;
  - then the SRV records they name, by priority and weight;
  - then the targets' addresses.
  - Lookups block, so they run on a discovery thread, never on the auth thread. The first request for an unknown
    realm starts the lookup and is not answered; the NAS's retransmission finds the result.
  - Results are kept for `proxy.discovery.ttl` (1 h), failures and empty answers for
    `proxy.discovery.negative.ttl` (5 min).
  - Discovered servers are TLS home servers like configured ones, with `proxy.discovery.tls.*` and the secret
    `radsec`. Their certificate must carry the SRV target's name, the classic TLS name check. Matching it against
    the NAI realm instead is not covered.
- **Metrics**: `radiusward_gateway_proxy_requests_total{home,result}` and `radiusward_gateway_proxy_home_alive{home}`.

## Consequences
- Proxied users never reach the identity stores, the workers or Simultaneous-Use. The home server decides, and its
  reply items go to the NAS as they are.
- Accounting of proxied users is committed and answered by the cluster like any other; nothing the home server does
  can lose it or keep the NAS waiting.
- Not covered: CoA from a home server back through the gateway to the NAS.
