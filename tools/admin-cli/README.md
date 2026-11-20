# radiusward-admin-cli

The administration commands of a radiusward cluster: the replicated state, the sinks and their checkpoints, export
checks, state-machine versions, and CoA and Disconnect-Requests through a RADIUS server. Cluster queries go through
the cluster log (`StateQuery`, `SessionQuery`, `SinkQuery`), so every answer includes everything committed before
it. `radiusward-admin-cli` is shipped in `radiusward.jar` (the distribution) and the container image as
`radiusward admin`.

**Stability:** Internal: published as a dependency of the distribution (`radiusward.jar`) and `radiusward-embedded`; it may change in any release.

## Use it

You normally do not depend on it directly: run it from `radiusward.jar` or the image. In tests,
[`radiusward-embedded`](../../embedded/README.md) answers the same questions (`session(...)`, `activeSessions(...)`,
`coa(...)`, `disconnect(...)`).

```bash
java -jar radiusward.jar admin state --members h0,h1,h2          # the distribution
docker run --rm radiusward:dev admin state --members h0,h1,h2     # the image
```

## What's inside

| Command | What it does |
|---|---|
| `state` | applied / duplicates / stale / rejected counts, sessions, state digest |
| `verify-acks` | every session's last acknowledged event (from `radclient load --ack-log`) is in the replicated state |
| `sinks` | per sink: checkpoint, lag in bytes, lease owner and epoch, required, detached, resync pending |
| `resync` | moves a sink's checkpoint (also backwards), fences its exporter with a new epoch and re-attaches it; the next exporter re-exports from there. Sinks are idempotent, so exporting again changes nothing; the log must still hold the position (`radiusward_log_start_bytes`) |
| `export-schema` | the full SQL of a built-in sink (`postgres`), with its `schema_version` rows, for DBAs (`schema.manage=none`) |
| `verify-export` | every session of an ack log is in `accounting_session` with at least the acknowledged progress; with `--members` it must equal the replicated session |
| `activate-version` | switches the cluster to a newer state-machine version at this log position; refused unless every member runs a release that knows it (normally automatic, see [release.md](../../docs/operations/release.md#upgrading-a-cluster)) |
| `disconnect`, `coa` | Disconnect-Request or CoA-Request to every session of `--user`, or to `--nas` + `--session`, through a RADIUS server's CoA API (`--server`, token from `--token` or `RADIUSWARD_COA_API_TOKEN`); exit 1 unless every session acknowledged ([ADR 0036](../../docs/adr/0036-coa-and-session-identity.md)) |

The classes: `AdminMain` (the command line), `AdminClient` (the cluster client behind the queries; the test harness
and the end-to-end tests use it directly), `AckVerifier`, `ExportVerifier`.

## Example

```bash
radiusward admin state          --members h0,h1,h2 [--base-port 9000] [--egress-host <own address>]
radiusward admin verify-acks    --members h0,h1,h2 --ack-log acks.csv --nas-id 1001
radiusward admin sinks          --members h0,h1,h2
radiusward admin resync         --members h0,h1,h2 --sink pg --position 0
radiusward admin export-schema  [--type postgres]
radiusward admin verify-export  --jdbc-url jdbc:postgresql://db/radius --jdbc-user u --jdbc-password p \
                                --ack-log acks.csv --nas-id 1001 [--members h0,h1,h2]
radiusward admin activate-version --members h0,h1,h2 --version 7
radiusward admin disconnect     --server http://server-a:9190 --user alice          # or --nas <entry> --session <id>
radiusward admin coa            --server http://server-a:9190 --user alice --attributes 'Session-Timeout = 600'
```

- `verify-acks` and `verify-export` take `--identity nas-identifier` when the NAS entry identifies the devices behind
  it by NAS-Identifier ([ADR 0019](../../docs/adr/0019-nas-device-identity.md)): the session keys then include the ack
  log's `nas_identifier`.
- `--egress-host` is an address of this machine the members can reach: `localhost` locally (the default), the
  container address inside Docker.
- `disconnect` and `coa` need `coa.api.token` set on the RADIUS server
  ([configuration.md](../../docs/configuration.md#coa-and-disconnect-server)).
- Exit codes: `0` ok, `1` something missing or no answer, `64` usage.

## Requirements

- Java 25.
- `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` for Agrona and Aeron; `radiusward.jar` sets it in its
  manifest.
- Depends on `radiusward-protocol`, `radiusward-server` and `radiusward-sink-postgres` (with the PostgreSQL JDBC
  driver, BSD-2-Clause); Aeron and Agrona (Apache-2.0).

## Learn more

- [Export](../../docs/operations/export.md): operating sinks, `resync`, `verify-export`
- [Release and upgrades](../../docs/operations/release.md), [ADR 0005: log determinism and versioning](../../docs/adr/0005-log-determinism-versioning.md)
- [ADR 0036: CoA and session identity](../../docs/adr/0036-coa-and-session-identity.md)
- [`radiusward-radclient`](../radclient/README.md), [`distribution`](../../distribution/README.md),
  [test harness](../../testing/test-harness/README.md)

## License

Apache-2.0.
