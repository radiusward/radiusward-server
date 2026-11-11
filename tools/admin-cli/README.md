# admin-cli

`radiusward admin`: the replicated state, sinks and export checks, state versions, CoA and Disconnect. Cluster queries go through the cluster log
(`StateQuery`, `SessionQuery`, `SinkQuery`), so every answer includes everything committed before it.

```bash
radiusward admin state          --members h0,h1,h2 [--base-port 9000] [--egress-host <own address>]
radiusward admin verify-acks    --members h0,h1,h2 --ack-log acks.csv --nas-id 1001
radiusward admin sinks          --members h0,h1,h2
radiusward admin resync         --members h0,h1,h2 --sink pg --position 0
radiusward admin export-schema  [--type postgres]
radiusward admin verify-export  --jdbc-url jdbc:postgresql://db/radius --jdbc-user u --jdbc-password p \
                                --ack-log acks.csv --nas-id 1001 [--members h0,h1,h2]
radiusward admin activate-version --members h0,h1,h2 --version 7
radiusward admin disconnect     --gateway http://gw:9190 --user alice          # or --nas <entry> --session <id>
radiusward admin coa            --gateway http://gw:9190 --user alice --attributes 'Session-Timeout = 600'
```

| Command | What it does |
|---|---|
| `state` | applied / duplicates / stale / rejected counts, sessions, state digest |
| `verify-acks` | every session's last acknowledged event (from `radclient load --ack-log`) is in the replicated state |
| `sinks` | per sink: checkpoint, lag in bytes, lease owner and epoch, required, detached, resync pending |
| `resync` | moves a sink's checkpoint (also backwards), fences its exporter with a new epoch and re-attaches it; the next exporter re-exports from there. Sinks are idempotent, so exporting again changes nothing; the log must still hold the position (`radiusward_log_start_bytes`) |
| `export-schema` | the full SQL of a built-in sink, with its `schema_version` rows, for DBAs (`schema.manage=none`) |
| `disconnect`, `coa` | Disconnect-Request or CoA-Request to every session of `--user`, or to `--nas` + `--session`, through a gateway's CoA API (`--gateway`, token from `--token` or `RADIUSWARD_COA_API_TOKEN`); exit 1 unless every session acknowledged ([ADR 0036](../../docs/adr/0036-coa-and-session-identity.md)) |
| `activate-version` | switches the cluster to a newer state-machine version at this log position; refused unless every member runs a release that knows it (normally automatic, see [release.md](../../docs/operations/release.md#upgrading-a-cluster)) |
| `verify-export` | every session of an ack log is in `accounting_session` with at least the acknowledged progress; with `--members` it must equal the replicated session |

`verify-acks` and `verify-export` take `--identity nas-identifier` when the NAS entry identifies the devices behind
it by NAS-Identifier ([ADR 0019](../../docs/adr/0019-nas-device-identity.md)): the session keys then include the ack
log's `nas_identifier`.

- `--egress-host` is an address of this machine the members can reach: `localhost` locally, the container
  address inside Docker.
- Exit codes: `0` ok, `1` something missing or no answer, `64` usage.

`AdminClient` is the library behind it; the test harness and the end-to-end tests use it directly.
