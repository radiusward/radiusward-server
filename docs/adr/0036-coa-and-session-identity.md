# ADR 0036: CoA and Disconnect, and sessions' identifying attributes

Status: Accepted (2026-11-10). Phase 5, work package 5.12 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)): session
identity in the replicated state, sender and API, Simultaneous-Use, store sweep, interop.

## Context
RFC 5176 lets a server change (CoA-Request) or end (Disconnect-Request) a session on the NAS. The request must name
the session in the NAS's terms: Acct-Session-Id, User-Name, often Framed-IP-Address, Calling-Station-Id or
NAS-Port, and the NAS's own NAS-IP-Address or NAS-Identifier.

The replicated session state (ADR 0012) kept only 128-bit keys, counters and, since state version 6, hashes of user
and device. Three triggers were decided:
- the admin API, by user or by session;
- Simultaneous-Use: disconnect the oldest session instead of rejecting a new one;
- store changes: a disabled or regrouped user, found by a rate-limited sweep.

Each needs those attributes, for any session, from any gateway, also after restarts.

## Decision
- **Identity in the replicated state** (state version 7, `atLeast(7)`). The state machine takes the identifying
  attributes from the attribute section that every `AccountingCommand` already carries for export, in order of
  importance while they fit 127 bytes:
  - Acct-Session-Id, User-Name, NAS-IP-Address, NAS-IPv6-Address, Framed-IP-Address, Calling-Station-Id,
    NAS-Identifier, NAS-Port, NAS-Port-Id, Called-Station-Id.
  - They are kept as RADIUS attributes, ready to copy into a request, per active session in a 128-byte slot.
  - Every applied event replaces them; the session's first event time (`firstSeen`) is set once.
  - Both enter the state digest, and snapshot version 7 carries them.
  - The extraction is pure and allocation-free, and reads the command with a decoder of its own, so the exporter
    still reads the command's variable fields.
  - Before activation they are ignored, as by older members. A session started before then gets its identity with
    its next event.
- **Memory** (ADR 0004, 0012): 64 bytes per session (63 bytes of attributes), off-heap, allocated with a storage
  chunk's first identity, so a cluster below version 7 pays nothing.
  - The exporter's replica shares the member's JVM, its outcomes never depend on users, devices or identities, and
    it never sends a CoA. It keeps no member state at all (`memberState(false)`).
  - On the way, `OverloadIT` showed that the small profile had stopped holding its 2M-session maximum in 1 GiB since
    state version 6, because of the per-user maps and the replica's copy of every column on a 384 MB heap. The first
    two attempts, 128-byte identities on the heap with a 640 MB heap, then off-heap with a 384 MB heap, both ran out
    of heap.
  - The fix compacts the whole session store into off-heap records (ADR 0012). At 2M sessions the state is ~60 MB
    of heap and ~460 MB direct for member and replica. The small member runs with `-Xmx256m
    -XX:MaxDirectMemorySize=576m` in its 1 GiB.
- **Queries** (protocol version 7):
  - `SessionReport` carries the identity.
  - `UserSessionsQuery`/`UserSessionsReport` list a user's active sessions (key, NAS, first and last event,
    identity), at most 64.
  - `SessionPageQuery`/`SessionPageReport` page through active sessions with a user, for the store sweep.
  - Both scan the store: operator and sweep questions, not per-packet work.
  - `AdminClient.session`, `userSessions` and `sessionPage` expose them.

- **Sending** (milestone 2): `DynamicAuthorization`, one gateway thread.
  - Disconnect-Request (40) and CoA-Request (43) are signed like an Accounting-Request and always carry a
    Message-Authenticator.
  - Each request gets an identifier free for its destination.
  - A response counts only if its Response Authenticator, and its Message-Authenticator if present, verify.
    ACK and NAK come back with the NAK's Error-Cause.
  - Without an answer, the request is sent again every `coa.timeout` (2 s) up to `coa.retries` (2) times, then it
    is a timeout.
- **Where to**:
  - Over the NAS's RadSec connection, if it has one (RFC 6614 lets both sides send on it), with its RadSec secret.
  - Otherwise over its DTLS association, if it has one, with its DTLS secret (RFC 7360 §2.4, [ADR 0038](0038-dtls.md)).
  - Otherwise over UDP to `nas.<name>.coa.address`, else the entry's address if it is a single one, else the
    session's NAS-IP-Address. The port is `nas.<name>.coa.port` (3799), the secret `nas.<name>.coa.secret` (else
    the entry's).
  - A NAS-IP-Address is added when the identity names no NAS and the entry has a single address.
- **Finding the sessions**: the gateway asks the cluster through its client session (`ClusterQueries`), by user or
  by NAS entry and Acct-Session-Id.
  - Entries that tell devices apart are addressed by user only.
  - A session without an identity yet (applied before version 7) is reported unreachable.
- **API**: on the gateway's management port, only with `coa.api.token` (at least 16 characters, compared in
  constant time):
  - `POST /coa/disconnect?user=` or `?nas=&session=`.
  - `POST /coa/update?user=` with a body of attributes in the users-file syntax, encoded with the dictionary.
  - The answer is one JSON result per session: `ack`, `nak` with `errorCause`, `timeout` or `unreachable`.
  - The work runs on its own threads, so a slow NAS never holds up `/health`.
  - `admin disconnect` and `admin coa` call it.
- **Metrics**: `radiusward_gateway_coa_requests_total{result}`, and RadSec's `coa_sent`, `coa_no_connection` and
  `coa_answers`.

- **Simultaneous-Use** (milestone 3, `coa.simultaneous.use = disconnect-oldest`; default `reject`): when the
  cluster denies a new device its place, the access worker asks for the user's sessions and sends the oldest one, by
  first event, a Disconnect-Request.
  - Once the NAS acknowledged, the worker asks for the place again every 100 ms while the NAS's Accounting-Stop is
    on its way, for at most `coa.simultaneous.use.wait` (3 s).
  - Up to 3 sessions, oldest first.
  - The NAS's retransmissions of the new Access-Request meanwhile are dropped as in flight.
  - Sessions without an identity (from before version 7) are skipped.
  - `radiusward_gateway_simultaneous_use_disconnects_total{result}` counts the disconnects.
  - The cluster keeps deciding alone: it frees the place only when the Stop is applied, so the limit is never
    exceeded, even while a NAS is slow to send the Stop.

- **Store sweep** (milestone 4, `coa.sweep.enabled` on one gateway): every `coa.sweep.interval` (15 min) the
  gateway pages through the active sessions with a user (`SessionPageQuery`) and looks each user up again, at most
  `coa.sweep.rate` (20) lookups per second.
  - The lookup is the login's authorization, checks and groups included, against a request made of the session's
    identifying attributes. Conditions on other attributes do not match there.
  - A user the stores now reject (disabled, `Auth-Type := Reject`) gets a Disconnect-Request on every session, and
    again at every sweep while a session is still active (its NAS refused, or sent no Stop).
  - A user whose reply items, filtered for the NAS's vendors, changed since the previous sweep gets a CoA-Request
    with all of them. The first sweep only records them.
  - A user no store has any more is kept, because EAP-TLS devices with a certificate alone are in no store, unless
    `coa.sweep.missing = disconnect`.
  - A store outage changes nothing.
  - Running the sweep on two gateways only repeats requests: a NAS NAKs a session it no longer has.
  - `radiusward_gateway_store_sweep_total{result}` counts sweeps, users, disconnects, changes and outages.

- **Interop** (milestone 5): `ExternalCoaReceiverIT` (`-Pinterop`, skipped without an installed `radiusd`) starts an
  external RADIUS server with a configuration of its own: a CoA listener that requires Message-Authenticator and
  refuses one user.
  - It acknowledges our Disconnect-Request and our CoA-Request with a Session-Timeout, and NAKs the refused user.
  - It drops a request with the wrong secret, which our sender reports as a timeout.
  - Its log ends up in `gateway/target/external-coa-receiver`.

## Consequences
- Any gateway can name any active session to its NAS, and that survives member restarts and snapshots.
- Session state is native memory now: an operator who starts members without the image's entrypoint must set
  `-XX:MaxDirectMemorySize` (~240 bytes per session for member and replica, plus a margin); the heap can be smaller.
- NAS-IP-Address and the other lower-priority attributes may not fit 63 bytes behind a long Acct-Session-Id and
  User-Name. The NAS entry's own address is then used to reach the NAS (milestone 2).
- The following milestones build on it: the sender with ACK/NAK and retries and the admin API (2), Simultaneous-Use
  disconnecting the oldest session (3), the store sweep (4), interop with a CoA listener (5).
