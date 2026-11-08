# radiusward

A replicated RADIUS accounting server for Java, built on [Aeron Cluster](https://github.com/aeron-io/aeron).

radiusward answers an Accounting-Request only after the record is **durably committed on a majority
of a three-node cluster** (fsync on), so an acknowledged accounting record survives the loss of any
single node. Duplicate and retransmitted requests — including retries that arrive through another
gateway after a failover — are recognised and answered without being counted twice.

> **Status:** Phase 0 complete — RADIUS codec, dictionaries, code generation, test client, docs.
> The cluster and gateway arrive in Phase 1. See the [roadmap](docs/plans/roadmap.md).

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

## Quickstart (Phase 0)

Requirements: JDK 21+ (CI also tests 25). No Docker needed.

```bash
./mvnw verify                                        # build + all tests
java -jar tools/radclient/target/radclient.jar decode \
     radius-codec/src/test/resources/fixtures/cisco/start.fixture
```

Send accounting to any RADIUS server (for example a local FreeRADIUS):

```bash
java -jar tools/radclient/target/radclient.jar acct \
     --server 127.0.0.1:1813 --secret testing123 \
     --status start --session-id abc123 --user alice --vendor cisco
```

More in [docs/operations/local-dev.md](docs/operations/local-dev.md).

## Modules

| Module | What it is |
|---|---|
| [`radius-dictionary`](radius-dictionary/README.md) | FreeRADIUS-format dictionary parser and attribute tree |
| [`radius-dictionary-freeradius`](radius-dictionary-freeradius/README.md) | Bundled FreeRADIUS dictionaries (CC BY 4.0) |
| [`radius-codegen`](radius-codegen/README.md) | Generates constants and the hot-attribute extractor |
| [`radius-codec`](radius-codec/README.md) | Zero-allocation RADIUS packet codec |
| [`tools/radclient`](tools/radclient/README.md) | Command-line accounting test client |
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
