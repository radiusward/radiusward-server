# radiusward

A replicated RADIUS accounting server for Java, built on [Aeron Cluster](https://github.com/aeron-io/aeron).

radiusward answers an Accounting-Request only after the record is **durably committed on a majority
of a three-node cluster** (fsync on), so an acknowledged accounting record survives the loss of any
single node. Duplicate and retransmitted requests — including retries that arrive through another
gateway after a failover — are recognised and answered without being counted twice.

> **Status:** Phase 1 complete — a replicated accounting cluster (3 Aeron Cluster members, 2 gateways)
> running locally without Docker, proven with `kill -9` failover tests. Containers arrive in Phase 2.
> See the [roadmap](docs/plans/roadmap.md).

## Architecture in short

```text
 NAS devices ──UDP──▶ gateway A ─┐                      ┌──▶ sink: Postgres
                     gateway B ─┼─▶ Aeron Cluster ──────┤
                                │   (3 nodes, Raft,     └──▶ sink: Kafka, ...
                                │    fsync, dedup)
 Accounting-Response ◀──────────┘   only after commit
```

- **Gateways** (stateless, NIO): own the UDP socket, validate and authenticate packets, extract the
  hot attributes without allocating, forward to the cluster, reply after commit.
- **Cluster** (Aeron Cluster, 3 nodes): replicated, fsynced log; per-session deduplication; snapshots.
- **Exporter** (Phase 3): tails the committed log into pluggable sinks (Postgres first, plain JDBC).

Details: [docs/architecture.md](docs/architecture.md) · what an ACK guarantees:
[docs/accounting-contract.md](docs/accounting-contract.md) · decisions: [docs/adr](docs/adr).

## Quickstart

Requirements: JDK 21+ (CI also tests 25). No Docker needed.

```bash
./mvnw verify                          # build + unit/integration tests (~1 min)
scripts/run-local.sh start             # 3 cluster members + 2 gateways as separate JVMs
scripts/run-local.sh wait-ready && scripts/run-local.sh status

java -jar tools/radclient/target/radclient.jar acct --server 127.0.0.1:1813 --secret testing123 \
     --status start --session-id abc123 --user alice --vendor cisco

scripts/run-local.sh demo-failover     # load through both gateways, kill -9 the leader, nothing lost
./mvnw -Pe2e verify                    # end-to-end tests against real processes
```

More in [docs/operations/local-cluster.md](docs/operations/local-cluster.md) and
[docs/configuration.md](docs/configuration.md).

## Modules

| Module | What it is |
|---|---|
| [`protocol`](protocol/README.md) | SBE messages between gateways, cluster and tools |
| [`common`](common/README.md) | configuration, profiles, management HTTP server, non-blocking logging |
| [`cluster-service`](cluster-service/README.md) | deterministic accounting state machine (dedup, sessions, snapshots) |
| [`cluster-node`](cluster-node/README.md) | launches a cluster member |
| [`gateway`](gateway/README.md) | RADIUS UDP gateway |
| [`distribution`](distribution/README.md) | the runnable `radiusward.jar` |
| [`radius-dictionary`](radius-dictionary/README.md) | FreeRADIUS-format dictionary parser and attribute tree |
| [`radius-dictionary-freeradius`](radius-dictionary-freeradius/README.md) | Bundled FreeRADIUS dictionaries (CC BY 4.0) |
| [`radius-codegen`](radius-codegen/README.md) | Generates constants and the hot-attribute extractor |
| [`radius-codec`](radius-codec/README.md) | Zero-allocation RADIUS packet codec |
| [`tools/radclient`](tools/radclient/README.md) | Command-line accounting test client |
| [`testing/test-harness`](testing/test-harness/README.md) | in-JVM local cluster, dev mode, admin client |
| [`testing/e2e-tests`](testing/e2e-tests/README.md) | end-to-end tests against real processes (`-Pe2e`) |
| [`testing/benchmarks`](testing/benchmarks/README.md) | JMH benchmarks |

## Supported vendors

All 190+ vendors in the bundled FreeRADIUS dictionaries are decoded. Cisco, Juniper (Junos 2636 and
ERX/Unisphere 4874 for MX subscriber management), MikroTik, Huawei, Meraki and Ruckus additionally
have generated accessors, deduplication profiles (Phase 1)
and test fixtures. Operators can add or override dictionaries in `/etc/radiusward/dictionary.d/`
([docs/dictionaries.md](docs/dictionaries.md)).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

### Third-party resources

The RADIUS dictionary files in `radius-dictionary-freeradius` come from the
[FreeRADIUS](https://freeradius.org/) project and are licensed under the
[Creative Commons Attribution 4.0 International License (CC BY 4.0)](radius-dictionary-freeradius/LICENSE-CC-BY-4.0.txt).
Copyright The FreeRADIUS Server project and contributors. Source commit and the one change made are
recorded in [NOTICE](NOTICE) and [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
