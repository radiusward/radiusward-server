# admin-cli

`radiusward admin`: the replicated state, sinks and export checks. Cluster queries go through the cluster log
(`StateQuery`, `SessionQuery`, `SinkQuery`), so every answer includes everything committed before it.

```bash
radiusward admin state          --members h0,h1,h2 [--base-port 9000] [--egress-host <own address>]
radiusward admin verify-acks    --members h0,h1,h2 --ack-log acks.csv --nas-id 1001
radiusward admin sinks          --members h0,h1,h2
radiusward admin resync         --members h0,h1,h2 --sink pg --position 0
radiusward admin export-schema  [--type postgres]
radiusward admin verify-export  --jdbc-url jdbc:postgresql://db/radius --jdbc-user u --jdbc-password p \
                                --ack-log acks.csv --nas-id 1001 [--members h0,h1,h2]
```

| Command | What it does |
|---|---|
| `state` | applied / duplicates / stale / rejected counts, sessions, state digest |
| `verify-acks` | every session's last acknowledged event (from `radclient load --ack-log`) is in the replicated state |
| `sinks` | per sink: checkpoint, lag in bytes, lease owner and epoch, required, detached, resync pending |
| `resync` | moves a sink's checkpoint (also backwards), fences its exporter with a new epoch and re-attaches it; the next exporter re-exports from there. Sinks are idempotent, so exporting again changes nothing; the log must still hold the position (`radiusward_log_start_bytes`) |
| `export-schema` | the full SQL of a built-in sink, with its `schema_version` rows, for DBAs (`schema.manage=none`) |
| `verify-export` | every session of an ack log is in `accounting_session` with at least the acknowledged progress; with `--members` it must equal the replicated session |

- `--egress-host` is an address of this machine the members can reach: `localhost` locally, the container
  address inside Docker.
- Exit codes: `0` ok, `1` something missing or no answer, `64` usage.

`AdminClient` is the library behind it; the test harness and the end-to-end tests use it directly.
