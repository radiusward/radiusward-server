# radiusward

[![CI](https://github.com/radiusward/radiusward-server/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/radiusward/radiusward-server/actions/workflows/ci.yml)
[![CodeQL](https://github.com/radiusward/radiusward-server/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/radiusward/radiusward-server/security/code-scanning)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=radiusward_radiusward-server&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=radiusward_radiusward-server)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=radiusward_radiusward-server&metric=coverage)](https://sonarcloud.io/component_measures?id=radiusward_radiusward-server&metric=coverage)
[![Maintainability](https://sonarcloud.io/api/project_badges/measure?project=radiusward_radiusward-server&metric=sqale_rating)](https://sonarcloud.io/project/overview?id=radiusward_radiusward-server)
[![Integration tests](https://img.shields.io/endpoint?url=https://radiusward.github.io/radiusward-server/badges/integration.json)](https://radiusward.github.io/radiusward-server/integration/)
[![End-to-end tests](https://img.shields.io/endpoint?url=https://radiusward.github.io/radiusward-server/badges/e2e.json)](https://radiusward.github.io/radiusward-server/e2e/)
[![Fault injection](https://img.shields.io/endpoint?url=https://radiusward.github.io/radiusward-server/badges/linux.json)](https://radiusward.github.io/radiusward-server/linux/)
[![Kubernetes](https://img.shields.io/endpoint?url=https://radiusward.github.io/radiusward-server/badges/k8s.json)](https://radiusward.github.io/radiusward-server/k8s/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A replicated RADIUS server for Java — accounting and authentication — built on
[Aeron Cluster](https://github.com/aeron-io/aeron).

radiusward answers an Accounting-Request only after the record is **durably committed on a majority
of a three-node cluster** (fsync on), so an acknowledged accounting record survives the loss of any
single node. Duplicate and retransmitted requests — including retries that arrive through another
gateway after a failover — are recognised and answered without being counted twice.

Access-Requests are decided by the gateways from identity stores (users file, SQL, LDAP/Active Directory,
Netlogon); what must be shared between gateways — simultaneous-use counts, SIM sequence numbers — lives in the
same replicated state.

> **Status:** Phase 5 complete — authentication with PAP, CHAP, MS-CHAP and the EAP methods below, RadSec, DTLS and
> TCP, proxying, CoA/Disconnect, policies and pools; EAP-SIM, EAP-AKA and EAP-AKA′ with local SIM keys.
> Phases 0–3: replicated accounting, container image, durability proven on Linux with simulated power loss of all
> members, partitions, full disks and overload (2M sessions in 1 GiB per member), a crashed leader replaced in
> ~2.2 s without NAS retransmissions, export to PostgreSQL. Phase 4: a Helm chart and systemd units, members that
> reseed themselves after a lost disk, a continuous backup that restores a lost quorum, and 500k sessions under
> leader kills, partitions and node drains on Kubernetes without a lost request
> ([report](docs/plans/phase-4.md#phase-4-report)). Next: more sinks (Phase 3b) — see the [roadmap](docs/plans/roadmap.md).

## What it does

- **Accounting**: acknowledged only after the commit; deduplication of retransmissions across gateways;
  Accounting-On/Off; idle sessions closed; export to PostgreSQL, JSON-lines files, or forwarded to other RADIUS
  servers ([docs/accounting-contract.md](docs/accounting-contract.md)).
- **Authentication methods**: PAP, CHAP, MS-CHAPv1/v2, EAP-MD5, EAP-TLS, PEAP (MS-CHAPv2, GTC, TLS inside, crypto
  binding), TTLS (PAP, CHAP, MS-CHAP, EAP inside), TEAP, EAP-pwd, EAP-SIM, EAP-AKA, EAP-AKA′ (pseudonyms and fast
  re-authentication); TOTP as a second factor; stored passwords from cleartext to bcrypt, SHA-crypt, yescrypt and
  NT hashes.
- **Identity stores**: users file, SQL (`radcheck` layout), LDAP/Active Directory, Active Directory over Netlogon
  (pure Java); plug-in API for more.
- **Transports**: UDP over IPv4 and IPv6, RadSec (RADIUS over TLS), RADIUS over DTLS and over TCP; NAS entries by
  address, network or client certificate, or looked up in SQL on demand.
- **Policy**: check and reply items, groups, Simultaneous-Use across all gateways, login times, expiry, usage
  counters, IPv4 and IPv6 address pools, Chargeable-User-Identity, a small rule layer.
- **Proxying**: realms to pools of home servers over UDP, TLS, TCP or DTLS with failover and load balancing, RFC 7585
  discovery, per-realm rewriting, inner-tunnel proxying, CoA relay.
- **CoA and Disconnect**: by user or session through an HTTP API, disconnect-oldest for Simultaneous-Use.
- **Operations**: Prometheus metrics, per-request traces, an authentication log, delayed rejects, configuration
  reload on SIGHUP, container images.

## Architecture in short

```text
 NAS ──UDP/TLS/DTLS/TCP──▶ gateway A ─┐                       ┌──▶ sink: PostgreSQL
                           gateway B ─┼─▶ Aeron Cluster ──────┼──▶ sink: JSON files
                              │       │   (3 nodes, Raft,     └──▶ sink: RADIUS forwarding
                              │       │    fsync, dedup,
                              │       │    shared auth state)
 Accounting-Response ◀────────┼───────┘   only after commit
 Access-Accept/Reject ◀── identity stores (file, SQL, LDAP/AD, Netlogon) · home servers (proxying)
```

- **Gateways** (stateless, NIO): own the sockets, validate and authenticate packets, extract the hot attributes
  without allocating, forward accounting to the cluster and reply after commit; decide Access-Requests on worker
  threads from the identity stores.
- **Cluster** (Aeron Cluster, 3 nodes): replicated, fsynced log; per-session deduplication; snapshots; the shared
  state of authentication (reservations, sequence numbers).
- **Exporter** (inside every member): tails the committed log into pluggable sinks — PostgreSQL, JSON files and RADIUS
  forwarding built in, more on the [roadmap](docs/plans/roadmap.md#sinks).

Test reports of the integration, end-to-end, fault-injection and Kubernetes suites:
[radiusward.github.io/radiusward-server](https://radiusward.github.io/radiusward-server/).

Details: [docs/architecture.md](docs/architecture.md) · what an ACK guarantees:
[docs/accounting-contract.md](docs/accounting-contract.md) · decisions: [docs/adr](docs/adr) · every setting:
[docs/configuration.md](docs/configuration.md).

## Quickstart with Docker

```bash
./mvnw -q install -DskipTests && docker build -f deploy/docker/Dockerfile -t radiusward:dev .
docker compose -f deploy/compose/compose.yaml up -d --wait   # 3 members + 2 gateways, fsync on
docker compose -f deploy/compose/compose.yaml run --rm tools acct --server gateway-a:1813 \
     --secret testing123 --status start --session-id abc123
deploy/compose/demo-failover.sh                              # kill -9 the leader under load, nothing lost
```

Released images: `ghcr.io/radiusward/radiusward-server` ([docs/operations/docker.md](docs/operations/docker.md)).

## Kubernetes

```bash
helm install radiusward deploy/helm/radiusward -n radius --create-namespace -f my-values.yaml
```

Three members and two gateways, each gateway with its own address for the NAS's primary and secondary server —
[docs/operations/kubernetes.md](docs/operations/kubernetes.md).
On Amazon ECS: [docs/operations/aws-ecs.md](docs/operations/aws-ecs.md) with example CloudFormation and Terraform
templates in [deploy/aws](deploy/aws).

## Quickstart without Docker

Requirements: JDK 25+.

```bash
./mvnw verify                          # build + unit/integration tests (~1 min)
scripts/run-local.sh start             # 3 cluster members + 2 gateways as separate JVMs
scripts/run-local.sh wait-ready && scripts/run-local.sh status

java -jar tools/radclient/target/radclient.jar acct --server 127.0.0.1:1813 --secret testing123 \
     --status start --session-id abc123 --user alice --vendor cisco

scripts/run-local.sh demo-failover     # load through both gateways, kill -9 the leader, nothing lost
./mvnw -Pe2e verify                    # end-to-end tests against real processes
scripts/linux-tests.sh                 # fault injection in containers (needs Docker; nightly in CI)
```

More in [docs/operations/local-cluster.md](docs/operations/local-cluster.md) and
[docs/configuration.md](docs/configuration.md).

### Authentication in a few lines

```properties
gateway.auth.enabled = true
auth.stores = local
auth.store.local.type = file
auth.store.local.path = /etc/radiusward/users       # alice  Cleartext-Password := "secret"
auth.store.local.mschap = true                      # MS-CHAPv2 (PEAP) from Cleartext-Password
auth.eap.methods = peap, ttls, tls
auth.eap.tls.certificate = /etc/radiusward/server.pem
auth.eap.tls.key = /etc/radiusward/server.key
auth.eap.tls.ca = /etc/radiusward/ca.pem
```

Stores, methods, RadSec, proxying and policies: [docs/configuration.md](docs/configuration.md#identity-stores).

## Modules

| Module | What it is |
|---|---|
| [`protocol`](protocol/README.md) | SBE messages between gateways, cluster and tools |
| [`common`](common/README.md) | configuration, profiles, management HTTP server, non-blocking logging |
| [`cluster-service`](cluster-service/README.md) | deterministic accounting state machine (dedup, sessions, snapshots) |
| [`cluster-node`](cluster-node/README.md) | launches a cluster member |
| [`gateway`](gateway/README.md) | RADIUS gateway: accounting, authentication, EAP, RadSec/DTLS/TCP, proxying, CoA |
| [`export-api`](export-api/README.md) | sink plug-in API, canonical attribute encoding, migration runner |
| [`exporter`](exporter/README.md) | exports the committed log to sinks (lease, state-machine reducer) |
| [`sinks/postgres`](sinks/postgres/README.md) | PostgreSQL sink |
| [`sinks/file`](sinks/file/README.md) | JSON-lines sink |
| [`sinks/radius`](sinks/radius/README.md) | forwards accounting of proxied realms to their home servers |
| [`auth-api`](auth-api/README.md) | identity store plug-in API |
| [`stores/file`](stores/file/README.md) | users-file identity store |
| [`stores/sql`](stores/sql/README.md) | SQL identity store (`radcheck` schema) |
| [`stores/ldap`](stores/ldap/README.md) | LDAP/Active Directory identity store and bind verifier |
| [`verifiers/netlogon`](verifiers/netlogon/README.md) | Active Directory over Netlogon, pure Java (MS-CHAPv1/v2, PAP) |
| [`distribution`](distribution/README.md) | the runnable `radiusward.jar` |
| [`radius-dictionary`](radius-dictionary/README.md) | FreeRADIUS-format dictionary parser and attribute tree |
| [`radius-dictionary-freeradius`](radius-dictionary-freeradius/README.md) | Bundled FreeRADIUS dictionaries (CC BY 4.0) |
| [`radius-codegen`](radius-codegen/README.md) | Generates constants and the hot-attribute extractor |
| [`radius-codec`](radius-codec/README.md) | Zero-allocation RADIUS packet codec |
| [`tools/radclient`](tools/radclient/README.md) | Command-line test client: accounting and Access-Requests (PAP, CHAP, MS-CHAPv2), replays, decoding, load |
| [`tools/admin-cli`](tools/admin-cli/README.md) | queries the replicated state; verifies acknowledgement logs |
| [`testing/test-harness`](testing/test-harness/README.md) | in-JVM local cluster, dev mode |
| [`testing/e2e-tests`](testing/e2e-tests/README.md) | end-to-end tests against real processes (`-Pe2e`) |
| [`testing/linux-tests`](testing/linux-tests/README.md) | fault injection in containers: power loss, partitions, full disk, overload (`-Plinux`) |
| [`testing/benchmarks`](testing/benchmarks/README.md) | JMH benchmarks |
| `testing/coverage` | Aggregate coverage over unit + integration tests, module floors (`-Pcoverage`) |
| [`testing/eapol-test`](testing/eapol-test/README.md) | wpa_supplicant's `eapol_test` with its SIM/USIM simulator, for the EAP interop tests |
| [`testing/radsec-client`](testing/radsec-client/README.md) | radsecproxy and clients for the RadSec and DTLS interop tests |
| [`testing/samba-ad`](testing/samba-ad/README.md) | Samba AD domain controller for the LDAP and Netlogon tests |

## Supported vendors

All 190+ vendors in the bundled FreeRADIUS dictionaries are decoded. Cisco, Juniper (Junos 2636 and
ERX/Unisphere 4874 for MX subscriber management), MikroTik, Huawei, Meraki and Ruckus additionally
have generated accessors, deduplication profiles (Phase 1)
and test fixtures; Aruba, Ubiquiti UniFi, Open-Mesh and MikroTik hotspots have test fixtures too. Operators can add or override dictionaries in `/etc/radiusward/dictionary.d/`
([docs/dictionaries.md](docs/dictionaries.md)).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

### Third-party resources

The RADIUS dictionary files in `radius-dictionary-freeradius` come from the
[FreeRADIUS](https://freeradius.org/) project and are licensed under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](radius-dictionary-freeradius/LICENSE-CC-BY-4.0.txt).
Copyright The FreeRADIUS Server project and contributors. Source commit and the one change made are
recorded in [NOTICE](NOTICE) and [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
