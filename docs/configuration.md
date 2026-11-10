# Configuration

Properties files, one or more per process (`--config a.properties --config b.properties`, later files win).
Every key can be overridden by an environment variable — `cluster.node.id` → `RADIUSWARD_CLUSTER_NODE_ID` —
and values may reference the environment: `${env:NAS_SECRET}`, `${env:X:-default}` ([ADR 0010](adr/0010-configuration.md)).
Durations: `500ms`, `10s`, `5m`, `2h`. Sizes: `512`, `64k`, `4m`, `1g`. Examples: [config/local](../config/local).

## Common

| Key | Default | Meaning |
|---|---|---|
| `profile` | `small` | `small` \| `standard` \| `large` — Aeron term lengths, threading, idle strategy, logging ring, capacities ([ADR 0004](adr/0004-memory-budget.md)) |
| `management.http.enabled` | `true` | management HTTP server on/off |
| `management.http.host` | `127.0.0.1` | bind address (`0.0.0.0` inside a pod) |
| `management.http.port` | node: `9090+id`, gateway: `9189+gateway.id` | `/health`, `/ready`, `/state` |
| `cluster.members` | `localhost,localhost,localhost` | member hosts in member-id order (nodes and gateways) |
| `cluster.base.port` | `9000` | member *i* uses `base + 100·i + {ingress 0, consensus 1, log 2, catchup 3, archive 4, replication 5}` |

In the container image the entrypoint sets defaults (as environment variables, so files still win):
`cluster.data.dir=/var/lib/radiusward`, `cluster.aeron.dir=/dev/shm/radiusward-node`,
`gateway.aeron.dir=/dev/shm/radiusward-gateway`, `dictionary.dir=/etc/radiusward/dictionary.d`,
`management.http.host=0.0.0.0`; heap from `RADIUSWARD_PROFILE` ([docker.md](operations/docker.md)).

System properties: `radiusward.log.dir` (also write a rolling file), `radiusward.log.level` (default `INFO`).

## Cluster node

| Key | Default | Meaning |
|---|---|---|
| `cluster.node.id` | — (required) | index into `cluster.members` |
| `cluster.data.dir` | `.local/data` | archive and cluster directories go to `<dir>/node-<id>/` |
| `cluster.aeron.dir` | temp dir per node | Aeron media driver directory (`/dev/shm` on Linux) |
| `cluster.leader.heartbeat.timeout` | `1500ms` | leader failure detection; with the election timeout a crashed leader is replaced in ~2.2 s, below a 3 s NAS timeout ([ADR 0011](adr/0011-gateway-pipeline.md)) |
| `cluster.election.timeout` | `500ms` | how long a candidate waits for votes |
| `cluster.session.timeout` | `10s` | client session timeout |
| `cluster.version.hold` | `false` | keep a newer state-machine version off after an upgrade, so a rollback stays possible; activate with `admin activate-version` ([release.md](operations/release.md#upgrading-a-cluster)) |
| `cluster.client.sessions.max` | `256` | concurrent cluster client sessions: every gateway, two per sink on every member, one position reporter per member, admin tools |
| `archive.file.sync.level` | `2` | `0` page cache, `1` fsync data, `2` fsync data + metadata; the archive catalog and the cluster's recording log and node state use the same level. Below `2` a power loss can lose acknowledged events or stop members from starting (`PowerLossIT`) |
| `archive.segment.length` | `128m` | archive segment file size, a power of two of at least the term length; the log is purged in whole segments. **Fixed per recording**: a change only affects recordings created afterwards |
| `log.purge.enabled` / `log.purge.dry.run` | `true` / `false` | purge the log below what nobody needs ([ADR 0014](adr/0014-log-purge.md)); dry run only logs |
| `log.purge.interval` | `1m` | how often a member reports its log position and purges |
| `cluster.disk.min.free` | `1g` | below this free space in the data directory the member reports not ready (`/ready`, with the reason) and logs a warning; a full disk stops the member. `0` disables |
| `snapshot.interval` | `1h` | automatic snapshot on the leader; `0` disables |
| `service.max.sessions` | profile (small: 2,000,000) | session capacity; new sessions beyond it are rejected |
| `service.auth.reservations.max` | `65536` | simultaneous-use reservations held at once (state version 6, [ADR 0023](adr/0023-simultaneous-use.md)); beyond it limited users get no answer. Same on every member |
| `service.tombstone` | `1h` | how long a stopped session is kept to recognise retransmitted Stops and late Interims; an Interim for an unknown session with an Event-Timestamp older than this is stale and creates no session |
| `service.idle.timeout` | `2h` | remove sessions with no event for this long (lost Stop), unless their NAS entry sets `nas.<name>.idle.timeout`; the exported stop time is the session's last event |
| `service.exact.key.window` | `15m` | remember exact keys of events without progress values |
| `service.sweep.interval` | `60s` | housekeeping timer |

## Gateway

| Key | Default | Meaning |
|---|---|---|
| `gateway.id` | `1` | distinct per gateway |
| `gateway.listen.host` / `gateway.listen.port` | `0.0.0.0` / `1813` | RADIUS accounting socket |
| `gateway.socket.receive.buffer` | `4m` | `SO_RCVBUF` |
| `gateway.egress.host` | `localhost` | address the cluster sends replies to (the pod IP in Kubernetes) |
| `gateway.aeron.dir` | temp dir per process | embedded media driver directory |
| `gateway.threading` | `shared` (`dedicated` for large) | both agents on one thread, or one each |
| `gateway.idle.strategy` | profile: `backoff-100us` (small, standard), `busy-spin` (large) | how the gateway threads wait when idle: `sleep-1ms` \| `backoff-1ms` \| `backoff-100us` \| `busy-spin`; trades CPU for latency (measurements in [testing/strategy.md](testing/strategy.md#latency-in-containers-phase-2)) |
| `gateway.pending.capacity` | profile (small: 16,384) | requests in flight; beyond it packets are dropped |
| `gateway.pending.timeout` | `5s` | forget a request with no commit (the next retransmit is submitted again) |
| `gateway.retransmit.resubmit.after` | `1s` | a retransmit of a request pending longer than this is resubmitted ([ADR 0011](adr/0011-gateway-pipeline.md)) |
| `gateway.response.cache.ttl` | `30s` | how long committed requests are answered from the cache |
| `gateway.auth.enabled` | `false` | answer Access-Requests (Phase 5); needs `auth.stores` ([below](#identity-stores)). Status-Server (RFC 5997) is answered on both ports with a valid Message-Authenticator; on the accounting port only while the gateway is connected to the cluster |
| `gateway.auth.port` | `1812` | RADIUS authentication socket (non-blocking, [ADR 0020](adr/0020-authentication-path.md)) |
| `gateway.auth.workers` | `4` | threads that decide Access-Requests (they may wait for an identity store; the socket thread never does) |
| `gateway.auth.pending` | `256` | Access-Requests between the socket and the workers (power of two); beyond it requests are dropped |
| `gateway.auth.reply.cache.entries` / `gateway.auth.reply.cache.ttl` | `4096` / `10s` | replies kept to answer retransmissions (RFC 5080) |
| `gateway.auth.reservation.timeout` | `1s` | how long a worker waits for the cluster's answer for a user with `Simultaneous-Use`; without one the request is not answered ([ADR 0023](adr/0023-simultaneous-use.md)) |
| `gateway.auth.reservation.ttl` | `60s` | how long a granted place waits for the device's Accounting-Start (1s–65535s) |
| `dictionary.dir` | `/etc/radiusward/dictionary.d` | operator dictionaries, loaded after the bundled set if the directory exists |
| `debug.enabled` | `false` | allows `debug.*` keys; never in production |
| `debug.response.delay` | `0` | hold Accounting-Responses back (tests only; requires `debug.enabled=true`) |
| `debug.state.version.supported` | code's version | pretend the member's release knows another state version, to test upgrades (tests only; requires `debug.enabled=true`) |

## RadSec (gateway)

RADIUS over TLS (RFC 6614, [ADR 0034](adr/0034-radsec.md)): authentication and accounting on one TCP connection,
client certificates required. A connection belongs to the NAS entry of its source address, which must allow it.

| Key | Default | Meaning |
|---|---|---|
| `radsec.enabled` | `false` | accept RadSec connections on `gateway.listen.host` |
| `radsec.port` | `2083` | TCP port |
| `radsec.certificate` / `radsec.key` | — | the server's certificate chain and unencrypted PKCS#8 key, PEM |
| `radsec.ca` | — | CAs (PEM) that NAS client certificates must chain to; required |
| `radsec.versions` | `TLSv1.2, TLSv1.3` | enabled TLS versions |
| `radsec.revocation`, `radsec.crl`, `radsec.ocsp.url`, `radsec.ocsp.timeout`, `radsec.revocation.soft.fail`, `radsec.reload` | as `auth.eap.tls.*` | revocation of client certificates and reload of the files, as for EAP ([ADR 0033](adr/0033-client-certificates.md)) |
| `radsec.connections` | `256` | connections at once; more are closed right after accepting |
| `radsec.handshake.timeout` | `10s` | a connection that has not finished its TLS handshake by then is closed |
| `radsec.idle.timeout` | `0s` (never) | close a connection without traffic for this long (TCP keep-alive is on regardless) |
| `radsec.session.timeout` | `1h` | how long a TLS session may be resumed on reconnect; also how long a revoked certificate may keep resuming. Sessions are kept per gateway: the gateway sets `-Djdk.tls.server.enableSessionTicketExtension=false` unless given, because the JDK does not check the age of stateless tickets |
| `nas.<name>.radsec` | `false` | this NAS entry may connect over RadSec |
| `nas.<name>.radsec.secret` | `radsec` | the shared secret inside TLS (RFC 6614 §2.3) |
| `nas.<name>.radsec.identity` | — | a name the client certificate must carry (common name, DNS, e-mail or UPN); unset: any certificate of `radsec.ca` |
| `nas.<name>.address` omitted | | with `radsec = true` and `radsec.identity`: the entry is identified by its certificate alone, from any address (NAT, changing addresses), and never reached over UDP; a connection whose address has no RadSec entry is matched against these by name |

```properties
radsec.enabled     = true
radsec.certificate = /etc/radiusward/tls/radsec.pem
radsec.key         = /etc/radiusward/tls/radsec.key
radsec.ca          = /etc/radiusward/tls/nas-ca.pem
nas.branch-17.address         = 198.51.100.17
nas.branch-17.secret          = ${env:BRANCH17_SECRET}    # still used over UDP
nas.branch-17.radsec          = true
nas.branch-17.radsec.identity = wlc.branch-17.corp.example
```

### DTLS

RADIUS over DTLS 1.2 (RFC 7360, [ADR 0038](adr/0038-dtls.md)) on a UDP port, with the RadSec certificate, key, CAs,
revocation and reload (`radsec.certificate`, `radsec.key`, `radsec.ca`, ...) and `radsec.handshake.timeout`. It runs
with or without the TCP listener. One association per NAS address and port; one RADIUS packet per record.

| Key | Default | Meaning |
|---|---|---|
| `radsec.dtls.enabled` | `false` | accept DTLS associations on `gateway.listen.host` |
| `radsec.dtls.port` | `2083` | UDP port |
| `radsec.dtls.associations` | `256` | associations at once; a ClientHello beyond is dropped |
| `radsec.dtls.idle.timeout` | `15m` | close an association without traffic for this long (`0s`: never) |
| `radsec.dtls.retransmit` | `1s` | first retransmission of an unanswered handshake flight, doubled up to 8 times as long (RFC 6347 §4.2.4) |
| `nas.<name>.dtls` | `false` | this NAS entry may use DTLS |
| `nas.<name>.dtls.secret` | `radius/dtls` | the shared secret inside DTLS (RFC 7360 §2.1) |
| `nas.<name>.dtls.identity` | — | a name the client certificate must carry; unset: any certificate of `radsec.ca` |
| `nas.<name>.address` omitted | | with `dtls = true` and `dtls.identity`: the entry is identified by its certificate alone, as for RadSec |

```properties
radsec.dtls.enabled = true
radsec.certificate  = /etc/radiusward/tls/radsec.pem
radsec.key          = /etc/radiusward/tls/radsec.key
radsec.ca           = /etc/radiusward/tls/nas-ca.pem
nas.ap-cloud.address       = 203.0.113.0/24
nas.ap-cloud.secret        = ${env:AP_CLOUD_SECRET}
nas.ap-cloud.identity      = nas-identifier
nas.ap-cloud.dtls          = true
nas.ap-cloud.dtls.identity = controller.ap-cloud.example
```

## CoA and Disconnect (gateway)

The gateway changes or ends sessions on their NAS (RFC 5176, [ADR 0036](adr/0036-coa-and-session-identity.md)).
Sessions are found in the replicated state, so any gateway reaches any session.

| Key | Default | Meaning |
|---|---|---|
| `coa.enabled` | `false` | send CoA and Disconnect-Requests |
| `coa.timeout` / `coa.retries` | `2s` / `2` | wait for an ACK or NAK, then send again; after the retries the result is `timeout` |
| `coa.api.token` | — | bearer token of the HTTP API on the management port (`POST /coa/disconnect`, `/coa/update`); at least 16 characters, use `${env:...}`; without it there is no API |
| `coa.simultaneous.use` | `reject` | over a user's `Simultaneous-Use`: `reject` the new device, or `disconnect-oldest`: the user's oldest session gets a Disconnect-Request and the new device is let in once the NAS's Accounting-Stop freed the place |
| `coa.simultaneous.use.wait` | `3s` | how long the new device's Access-Request waits for that Stop (keep below the NAS's timeout × retries) |
| `coa.sweep.enabled` | `false` | the store sweep, on one gateway: users with active sessions looked up again; rejected now → Disconnect, changed reply items → CoA |
| `coa.sweep.interval` / `coa.sweep.rate` | `15m` / `20` | time between sweeps; store lookups per second at most (spare the directory) |
| `coa.sweep.missing` | `keep` | a user no store has any more: `keep` (EAP-TLS devices with a certificate alone are in no store) or `disconnect` |
| `nas.<name>.coa.address` | the entry's address, else the session's NAS-IP-Address | where the NAS's dynamic-authorization server listens (a NAS on RadSec gets the request on its connection instead) |
| `nas.<name>.coa.port` | `3799` | its UDP port |
| `nas.<name>.coa.secret` | `nas.<name>.secret` | its shared secret |

```bash
curl -X POST -H "Authorization: Bearer $RADIUSWARD_COA_API_TOKEN" 'http://gw:9190/coa/disconnect?user=alice'
curl -X POST -H "Authorization: Bearer $RADIUSWARD_COA_API_TOKEN" 'http://gw:9190/coa/update?user=alice' \
     --data 'Session-Timeout = 600, Filter-Id = "restricted"'
admin disconnect --gateway http://gw:9190 --user alice      # token from RADIUSWARD_COA_API_TOKEN
```

## Proxying (gateway)

Users of some realms are authenticated by other RADIUS servers ([ADR 0037](adr/0037-proxying.md)); needs
`gateway.auth.enabled`. A user without a configured realm is decided locally.

| Key | Default | Meaning |
|---|---|---|
| `proxy.enabled` | `false` | proxy the configured realms |
| `realm.<id>.name` | `<id>` | the realm (`user@realm`, `REALM\user`), case-insensitive; `*`: every realm no other entry names |
| `realm.<id>.pool` | — | the pool its users go to |
| `realm.<id>.strip` | `false` | send the user name without the realm |
| `pool.<id>.servers` | — | home servers in order |
| `pool.<id>.type` | `failover` | `failover` (the first one alive) or `load-balance` (by device, so an EAP conversation stays on one server) |
| `home.<id>.address` | — | `host[:port]`; port 1812 |
| `home.<id>.secret` | — (`radsec` over TLS) | its shared secret; use `${env:...}` |
| `home.<id>.transport` | `udp` | `udp`, or `tls`: RadSec (port 2083 by default) |
| `home.<id>.tls.certificate` / `home.<id>.tls.key` | — | our client certificate and unencrypted PKCS#8 key (PEM) for RadSec |
| `home.<id>.tls.ca` | — | CAs the home server's certificate must chain to; required with `tls` |
| `home.<id>.tls.name` | the address's host | a name the home server's certificate must carry (and SNI) |
| `realm.<id>.discover` | `false` | find the realm's RadSec home servers in DNS (RFC 7585: NAPTR `aaa+auth:radius.tls.tcp`, SRV, address) instead of a pool |
| `proxy.discovery.tls.ca` / `.certificate` / `.key` | — | CAs discovered servers must chain to (required), our client certificate and key; their certificate must carry the SRV target name |
| `proxy.discovery.ttl` / `proxy.discovery.negative.ttl` | `1h` / `5m` | how long a lookup, or a failed or empty one, is kept |
| `proxy.discovery.dns.server` | the system's | `host:port` of the DNS server to ask |
| `proxy.discovery.secret` | `radsec` | the secret over TLS |
| `proxy.timeout` / `proxy.retries` | `3s` / `2` | wait for an answer, then send again; afterwards the NAS gets none and asks again |
| `proxy.dead.after` | `30s` | a home server without any answer for this long while requests wait is skipped |
| `proxy.status.interval` | `10s` | Status-Server probes to every home server; an answer brings a dead one back |
| `proxy.pending` | `1024` | proxied requests in flight |
| `proxy.require.message-authenticator` | `true` | ignore answers without a valid Message-Authenticator (BlastRADIUS) |

## Identity stores

Gateways with `gateway.auth.enabled=true` ([ADR 0021](adr/0021-identity-stores.md)).

| Key | Default | Meaning |
|---|---|---|
| `auth.stores` | — (required) | store names, asked in this order; the first that knows the user decides |
| `auth.store.<name>.type` | — | `file`, `sql`, or the type of a plug-in |
| `auth.store.<name>.chap` | `false` | allow CHAP and EAP-MD5 with this store's `Cleartext-Password` |
| `auth.store.<name>.mschap` | `false` | allow MS-CHAPv1/v2 (also inside PEAP) to derive the NT hash from this store's `Cleartext-Password`; `NT-Password` needs no opt-in ([ADR 0024](adr/0024-ms-chap-and-status-server.md)) |
| `auth.store.<name>.path` | — | `file`: the users file |
| `auth.store.<name>.reload.interval` | `5s` | `file`: how often the file's modification time is checked |
| `auth.store.<name>.url` / `.user` / `.password` | — / empty / empty | `sql`: JDBC URL and credentials |
| `auth.store.<name>.pool` | `gateway.auth.workers` | `sql`: maximum connections |
| `auth.store.<name>.timeout` | `1500ms` | `sql`: wait for a connection, and query timeout; beyond it the store counts as unavailable |
| `auth.store.<name>.schema` | `radcheck` | `sql`: table layout (only `radcheck` so far) |
| `auth.store.<name>.table.<table>` | the table's name | `sql`: other names for `radcheck`, `radreply`, `radusergroup`, `radgroupcheck`, `radgroupreply` (`[schema.]name`) |
| `auth.store.<name>.verifier` | none | the credential verifier that checks users of this store without a password of their own ([ADR 0025](adr/0025-credential-verifiers-and-ldap.md)) |
| `auth.verifiers` | none | credential verifiers by name; `Auth-Type := <name>` sends a user to one |
| `auth.verifier.<name>.type` | — | `ldap` (PAP by binding as the user; settings as the LDAP store's, [stores/ldap](../stores/ldap/README.md)), `netlogon` (MS-CHAPv1/v2 and PAP against Active Directory: `server` or `dns.domain` (+ `dns.server`, `dns.refresh`), `domain`, `machine.account`, `machine.password`, `server.name`, `endpoint.mapper.port`, `netlogon.port`, `strip.realm`, `timeout`, `connections`; [verifiers/netlogon](../verifiers/netlogon/README.md)), or a plug-in's type |
| `auth.store.<name>.*` for `type = ldap` | | `url`, `tls.ca`, `bind.dn`, `bind.password`, `base.dn`, `user.filter`, `strip.domain`, `group.attribute`, `group.nested`, `require.groups`, `policy.<id>.group/check/reply`, `check.<attribute>`, `reply.<attribute>`, `timeout`, `pool` ([stores/ldap](../stores/ldap/README.md)) |
| `auth.eap.methods` | `md5` | EAP methods offered, in order of preference: `tls`, `peap`, `ttls`, `md5`; a peer may Nak to another listed one ([ADR 0026](adr/0026-eap-framework.md)). EAP-MD5 needs the store's `chap` opt-in |
| `auth.eap.tls.certificate` / `auth.eap.tls.key` | — | the server's certificate chain and its unencrypted PKCS#8 key, PEM ([ADR 0028](adr/0028-eap-tls.md)) |
| `auth.eap.tls.ca` | — | CA certificates (PEM) that client certificates must chain to; required for `tls`, not used by `peap` and `ttls` |
| `auth.eap.tls.versions` | `TLSv1.2, TLSv1.3` | enabled TLS versions |
| `auth.eap.tls.fragment.size` | `1024` | largest TLS payload per EAP message (64–3000) |
| `auth.eap.tls.max.message` | `65536` | largest TLS message a peer may send in fragments |
| `auth.eap.tls.require.user` | `false` | `true`: an EAP-TLS peer must also exist in an identity store; otherwise a valid certificate is enough |
| `auth.eap.tls.identity` | `match` | how a client certificate relates to the EAP identity: `match` (the identity must be its common name, an e-mail, DNS or UPN alternative name; `host/<name>` for Windows machines), `certificate` (the identity is ignored, the certificate's name is the user authorized), `any` (any valid certificate; only for stores without per-user rules) ([ADR 0033](adr/0033-client-certificates.md)) |
| `auth.eap.tls.revocation` | `none` | revocation check of client certificates: `none`, `crl` (from `auth.eap.tls.crl`; every issuer of the chain needs its CRL), `ocsp` (the certificate's responder or `auth.eap.tls.ocsp.url`; CRLs as fallback) |
| `auth.eap.tls.crl` | — | CRL files (PEM or DER), comma-separated; reloaded on change like the certificates |
| `auth.eap.tls.ocsp.url` / `auth.eap.tls.ocsp.timeout` | — / `2s` | an OCSP responder for every certificate instead of the certificate's own; connect and read timeout (unless set as JDK system properties) |
| `auth.eap.tls.revocation.soft.fail` | `false` | `true`: an unknown status (no CRL of the issuer, responder unreachable) passes; a revoked certificate still fails |
| `auth.eap.tls.session.timeout` | `1h` | how long an EAP TLS session may be resumed; PEAP and TTLS then skip their inner method for the user remembered with it, who is authorized again ([ADR 0035](adr/0035-eap-session-resumption.md)). Also how long a revoked certificate or a changed password goes unnoticed for a device that keeps resuming |
| `auth.eap.tls.reload` | `60s` | how often the certificate, key, CA and CRL files are checked for changes; a change that does not load keeps the previous ones; `0s` = never |
| `auth.eap.peap.inner` | `mschapv2` | inner methods PEAP offers, first preferred: `mschapv2`, `gtc` (a password checked like PAP), `tls` (a client certificate; needs `auth.eap.tls.ca`) ([ADR 0031](adr/0031-peap-inner-methods.md)) |
| `auth.eap.peap.crypto.binding` | `optional` | PEAP crypto-binding: `optional` (sent; a peer without support may answer without it, a wrong one fails), `required`, `off`; with a verified binding the keys come from the compound session key ([ADR 0032](adr/0032-peap-crypto-binding.md)) |
| `auth.eap.timeout` | `30s` | how long a conversation waits for the peer's next response |
| `auth.eap.conversations` | `10000` | EAP conversations held at once; beyond it new rounds are not answered |
| `auth.cache.ttl` / `auth.cache.max` | `5s` / `100000` | per-worker caches of look-ups, successful slow-hash checks and encoded reply items (each bounded by `max`) |
| `auth.bcrypt.max.cost` | `14` | highest bcrypt cost verified (4–31); a stored hash above it is rejected rather than tying up a worker (cost 14 ≈ 1 s of CPU) |
| `auth.plugins.dir` | `/opt/radiusward/plugins` | jars with further `IdentityStoreProvider`s |
| `nas.<name>.auth.stores` | all of `auth.stores` | the stores asked for this NAS entry, in order |
| `nas.<name>.reply.vendors` | from `nas.<name>.vendor` | vendors whose attributes this entry's Access-Accepts carry (dictionary vendor names, `all`, `none`); standard attributes are always sent ([ADR 0022](adr/0022-reply-attributes.md)). Without it: the vendor of `nas.<name>.vendor` if it names a dictionary vendor (`juniper` also gets `Unisphere`), else everything |

## Export

Cluster members; every member gets the same keys ([export.md](operations/export.md)).

| Key | Default | Meaning |
|---|---|---|
| `export.sinks` | — (none) | comma-separated sink names; empty disables the exporter |
| `export.lease.timeout` | `10s` | how long a sink's lease lasts without renewal (renewed every third of it) |
| `export.plugins.dir` | `/opt/radiusward/plugins` | jars with further sink types |
| `sink.<name>.type` | — (required) | `postgres`, `file`, or a plug-in's type |
| `sink.<name>.required` | `true` | a required sink holds the log and can block ACKs |
| `sink.<name>.max.lag` | `4h` | lag limit by time (from the first unexported entry) |
| `sink.<name>.max.lag.bytes` | `0` (off) | lag limit by log bytes |
| `sink.<name>.on.max.lag` | `block` if required, else `detach` | `block`: stop acknowledging new accounting; `detach`: release the log, alert |
| `sink.<name>.batch.rows` / `batch.linger` | `5000` / `200ms` | batch size and wait |
| `sink.<name>.mode` | `sessions` | `sessions` (one row per session) or `sessions+events` (plus history) |

PostgreSQL (`type=postgres`): `url` (required), `user`, `password`, `attributes` (`json` \| `raw` \| `none`,
default `json`), `schema.manage` (`auto` \| `validate` \| `none`), `events.retention` (default `90d`, `0` keeps
all), `sessions.retention` (closed sessions, default `0`: keep), `radacct.view` (`false`),
`connect.timeout.seconds` (`5`), `socket.timeout.seconds` (`120`). Plug-in settings are read from the files
(environment variables override keys that are present there).

File (`type=file`): `dir` (required), `mode`, `max.file.size` (`256m`).

## NAS clients (gateway)

| Key | Default | Meaning |
|---|---|---|
| `nas.<name>.address` | — | IPv4 address or CIDR range of the NAS |
| `nas.<name>.secret` | — | shared secret; use `${env:...}` |
| `nas.<name>.vendor` | `default` | vendor profile; a dictionary vendor name (`cisco`, `mikrotik`, …) also limits the vendor attributes in Access-Accepts (`reply.vendors`) |
| `nas.<name>.message-authenticator` | `optional` | `required` \| `optional` \| `off` |
| `nas.<name>.id` | FNV-1a hash of the name | identity used in event keys — must be identical on every gateway |
| `nas.<name>.access.message-authenticator` | `required` | Message-Authenticator on Access-Requests: `required` \| `optional` \| `off` (BlastRADIUS, CVE-2024-3596; always required with EAP) |
| `nas.<name>.idle.timeout` | cluster's `service.idle.timeout` | close a session of this NAS without an event for this long (lost Stop): about 3 × the NAS's interim interval, e.g. `15m` for 5-minute interims. Whole minutes, 1m–65535m; the latest event of a session sets it |
| `nas.<name>.identity` | `source-ip` | devices behind this entry (NAT, cloud Wi-Fi): `nas-identifier`, `called-station-id`, `nas-ip-address`, or a list (first present wins); required for `0.0.0.0/0`. Must be identical on every gateway |

**Devices behind NAT** ([ADR 0019](adr/0019-nas-device-identity.md)). When many access points reach the gateways
through one address, set `identity` so their sessions stay apart and an Accounting-On stops only the rebooted
device's sessions:

```properties
nas.meraki.address  = 203.0.113.10        # the site's NAT address; one entry per fleet or site
nas.meraki.secret   = ${env:MERAKI_SECRET}
nas.meraki.identity = nas-ip-address      # the attribute these devices send in EVERY accounting packet
nas.meraki.message-authenticator = required
```

From the (synthetic) vendor fixtures — confirm with a capture of your own devices:

| Devices | `identity` | Why |
|---|---|---|
| Aruba Instant / controller | `called-station-id` | the AP MAC in every packet (no separators) |
| Ubiquiti UniFi | `nas-identifier` | the AP MAC |
| Open-Mesh | `called-station-id` | NAS-Identifier is sent empty |
| Meraki | `nas-ip-address` (one entry per site address) | no NAS-Identifier; Called-Station-Id (BSSID) only in the Start |
| MikroTik hotspot | `nas-identifier` | Called-Station-Id is the hotspot server name |
| Ruckus | `nas-ip-address` | NAS-Identifier only in the Start |

Pick the attribute the devices send in every Start, Interim and Stop: a session whose packets resolve to different
attributes splits (watch `identity_fallback`). Check with a capture (`radclient decode`). A private NAS-IP-Address
can repeat across sites — one entry per site address, or NAS-Identifier. Changing `identity` changes session keys:
active sessions continue as new ones, the old ones end by the idle timeout.
