# ADR 0044: Proxying the inner user of a tunnel

Status: Accepted (2026-11-10). Phase 5, work package 5.20 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)).

## Context
Proxying (ADR 0037) sends a whole EAP conversation to a realm's home server when the outer identity names the realm.
Many sites instead end the tunnel themselves: the outer identity is anonymous (or another realm), the TLS server is
theirs, and only the inner user, `bob@partner.example`, belongs to another organisation. That organisation's server
checks the password; it does not need to run TLS for us. Other servers call this proxying the inner tunnel.

## Decision
- **`proxy.inner = true`**: when the inner identity of PEAP, TTLS or TEAP belongs to a proxied realm (not one that
  is discovered in DNS), its credential goes to that realm's home servers instead of the identity stores.
  - PAP, EAP-GTC and TEAP's Basic-Password-Auth go as User-Password.
  - CHAP and EAP-MD5 inside TTLS go as CHAP-Password and CHAP-Challenge.
  - MS-CHAPv2 (PEAP, TTLS, EAP-MSCHAPv2 inside TTLS or TEAP) goes as MS-CHAP-Challenge and MS-CHAP2-Response.
  - MS-CHAPv1 inside TTLS is not proxied.
  - User-Name is the inner identity, stripped of the realm if the realm says so, except for MS-CHAPv2: the peer's
    challenge hash covers the full name.
- **Inner checks carry the raw exchange**: `InnerAuth.msChapV2` gets the challenges and the response, not only our
  challenge hash. An MS-CHAPv2 acceptance carries either our NT hash's MD4 (local) or the home server's
  MS-CHAP2-Success and its MPPE send and receive keys (proxied). PEAP's ISK and crypto-binding, TEAP's inner MSK and
  TTLS's success all take the keys and authenticator response from whichever is there, so a proxied inner user gets
  the same protection as a local one.
- **Transport**: a blocking UDP client (`InnerProxy`) on the access workers, which may wait anyway (identity stores,
  verifiers).
  - The realm's UDP home servers are tried in pool order, each `proxy.retries` more times after `proxy.timeout`.
    Message-Authenticator is always sent, and required in answers with `proxy.require.message-authenticator`.
  - An Accept is a success; its MPPE keys are decrypted with the home server's secret.
  - A Reject or a Challenge is a failure.
  - No answer leaves the request unanswered, so the NAS sends it again, as when a store is down.
  - RadSec home servers are not used for inner proxying.
- **Authorization**: the home server decided, so its reply attributes, without MPPE keys, MS-CHAP2-Success, State,
  Proxy-State, EAP-Message and Message-Authenticator, are kept on the conversation and become our Accept's. The local
  stores are not asked about that user.
- **Resumption**: a tunnel whose inner user was proxied is not remembered for fast reconnect. A reconnect runs the
  inner method again, and the home server decides again.
- **Metrics**: `radiusward_gateway_inner_proxy_total{result}`: requests, accepted, rejected, no_answer.

## Tests
- `EapolTestIT#innerUsersOfAProxiedRealmAreCheckedByTheirHomeServer`: a second gateway plays the home server and alone
  knows `bob@partner.example`. Through the proxy:
  - PEAP-MSCHAPv2 with required crypto-binding, PEAP-GTC, TTLS-PAP, TTLS-MSCHAPv2, TTLS with EAP-MSCHAPv2 and
    TEAP-MSCHAPv2 succeed with matching keys, and the home server's Reply-Message reaches the NAS;
  - wrong passwords are rejected.
- `InnerProxyTest`: realms of inner users, User-Password and MPPE key encryption, stripping, an unanswering home
  server leaving the request unanswered.
- The earlier EAP tests pass unchanged with the raw MS-CHAPv2 exchange.
