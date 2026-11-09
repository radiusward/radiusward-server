# Monitoring

Every member and gateway serves `/metrics` in the Prometheus text format on its management port (9090 in the
container image), next to `/health`, `/ready` and `/state`. It is written from counters the components keep
anyway — no client library, nothing computed per packet.

```bash
curl -s http://127.0.0.1:9090/metrics      # a member (local: scripts/run-local.sh, ports 9090-9092)
docker compose -f deploy/compose/compose.yaml --profile monitoring up -d --wait
# Prometheus http://127.0.0.1:9095 (rules loaded), Grafana http://127.0.0.1:3000 (dashboard "radiusward")
```

OpenTelemetry users (Datadog, New Relic, Grafana Cloud …) let an OpenTelemetry Collector scrape `/metrics` with
its Prometheus receiver; radiusward needs no OpenTelemetry SDK.

## Metrics

Names carry the unit (`_bytes`, `_seconds`); counters end in `_total`. Members are labelled `member`, gateways
`gateway`, sinks `sink`.

### Cluster member

| Metric | Type | Meaning |
|---|---|---|
| `radiusward_cluster_leader` | gauge | 1 on the leader |
| `radiusward_cluster_leader_member` | gauge | member id of the current leader, -1 while unknown |
| `radiusward_cluster_leadership_terms_total` | counter | leadership term id; increases with every election |
| `radiusward_cluster_log_position_bytes` | gauge | log position of the last accounting entry applied |
| `radiusward_accounting_events_total{outcome}` | counter | `applied`, `duplicate`, `stale`, `rejected` |
| `radiusward_accounting_export_lag_rejections_total` | counter | accounting not acknowledged because a required sink was over its `maxLag` |
| `radiusward_state_version{kind}` | gauge | state-machine version: `active` in the cluster, `supported` by this member's release, `lowest_supported` by all members (0 while one has not reported) ([ADR 0005](../adr/0005-log-determinism-versioning.md)) |
| `radiusward_state_version_held` | gauge | 1 while `cluster.version.hold` keeps a supported version off |
| `radiusward_nas_identity_mismatches_total` | counter | accounting from a gateway whose `nas.<name>.identity` differs from the entry's first one seen — configure every gateway alike ([ADR 0019](../adr/0019-nas-device-identity.md)) |
| `radiusward_sessions{state}` | gauge | `active`, `stopped` sessions in the replicated state |
| `radiusward_snapshots_total` | counter | snapshots taken |
| `radiusward_egress_dropped_total` | counter | replies to gateways given up under back pressure |
| `radiusward_disk_free_bytes`, `radiusward_disk_min_free_bytes` | gauge | data directory free space and `cluster.disk.min.free` |
| `radiusward_log_start_bytes` | gauge | lowest log position still on this member's disk |
| `radiusward_log_purge_floor_bytes` | gauge | position below which nobody needs the log ([ADR 0014](../adr/0014-log-purge.md)) |

### Export (members with `export.sinks`)

| Metric | Type | Meaning |
|---|---|---|
| `radiusward_export_exporting{sink}` | gauge | 1 on the member holding the sink's lease |
| `radiusward_export_lag_bytes{sink}` | gauge | accounting log not yet written by the sink |
| `radiusward_export_lag_seconds{sink}` | gauge | age of the newest exported entry while behind (exporting member) |
| `radiusward_export_detached{sink}` | gauge | 1 when an optional sink has been detached |
| `radiusward_export_epoch{sink}` | gauge | lease epoch; increases with every handover |
| `radiusward_export_rows_total{sink}`, `radiusward_export_batches_total{sink}` | counter | written by this member |
| `radiusward_export_last_batch_seconds{sink}` | gauge | duration of the last batch write |
| `radiusward_export_errors_total{sink}` | counter | failed writes and other sink errors (details: `lastError` on `/state`) |

### Gateway

| Metric | Type | Meaning |
|---|---|---|
| `radiusward_gateway_access_requests_total{result}` | counter | Access-Requests: `received`, `accepted`, `rejected`, `challenged`, `dropped`, `cache_hits`, `retransmit_in_flight`, `busy`, `message_authenticator_missing`, `message_authenticator_failed`, `handler_errors`, `unknown_nas`, … (with `gateway.auth.enabled`) |
| `radiusward_gateway_access_in_flight` / `radiusward_gateway_access_reply_cache_entries` | gauge | Access-Requests with the workers; replies kept for retransmissions |
| `radiusward_gateway_packets_total{result}` | counter | `received`, `committed`, `cache_hits`, `duplicates`, `stale`, `rejected`, `pending_full`, `ring_full`, `resubmitted`, `resubmitted_on_new_leader`, `malformed`, `unknown_nas`, `authenticator_failed`, `identity_missing`, `identity_fallback`, … (all gateway counters) |
| `radiusward_gateway_pending_requests` | gauge | requests waiting for a commit |
| `radiusward_gateway_response_cache_entries` | gauge | RFC 5080 response cache size |
| `radiusward_gateway_cluster_connected` | gauge | 1 while connected to the cluster |

### Every process

`radiusward_jvm_memory_used_bytes{area}`, `radiusward_jvm_memory_committed_bytes{area}`,
`radiusward_jvm_memory_max_bytes`, `radiusward_jvm_gc_collections_total{gc}`,
`radiusward_jvm_gc_pause_seconds_total{gc}`, `radiusward_jvm_threads`, `radiusward_process_uptime_seconds`,
`radiusward_log_messages_dropped_total` (logging ring full; the caller never blocks).

## Alerts

[deploy/monitoring/alerts.yml](../../deploy/monitoring/alerts.yml), checked with `promtool` in
`MonitoringConfigIT`:

| Alert | When | Severity |
|---|---|---|
| `RadiuswardNoLeader` | no member is leader for 30 s | critical |
| `RadiuswardFrequentElections` | more than 3 elections in 15 min | warning |
| `RadiuswardMemberDown` | a member's `/metrics` unreachable for 1 min | warning |
| `RadiuswardExportLagWarning` | a sink more than 2 h behind (half the default `maxLag`) | warning |
| `RadiuswardExportBlocking` | accounting rejected because a required sink is over `maxLag` | critical |
| `RadiuswardSinkDetached` | an optional sink was detached | warning |
| `RadiuswardSinkErrors` | more than 5 sink errors in 10 min | warning |
| `RadiuswardDiskLow` | free space below `cluster.disk.min.free` | critical |
| `RadiuswardGatewayDropping` | a gateway drops requests (pending table or ring full) for 5 min | warning |
| `RadiuswardGatewayDisconnected` | a gateway not connected to the cluster for 1 min | critical |

Adjust the export thresholds when you change `maxLag`, and route the alerts with your Alertmanager.
