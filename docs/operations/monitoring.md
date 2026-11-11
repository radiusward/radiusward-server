# Monitoring

Every member and gateway serves `/metrics` in the Prometheus text format on its management port (9090 in the
container image), next to `/health`, `/ready` and `/state`. It is written from counters the components keep
anyway — no client library, nothing computed per packet.

```bash
curl -s http://127.0.0.1:9090/metrics      # a member (local: scripts/run-local.sh, ports 9090-9092)
docker compose -f deploy/compose/compose.yaml --profile monitoring up -d --wait
# Prometheus http://127.0.0.1:9095 (rules loaded), Grafana http://127.0.0.1:3000 (dashboards tagged "radiusward")
docker compose -f deploy/compose/compose.yaml run --rm tools load --server gateway-a:1813,gateway-b:1813 \
    --secret testing123 --sessions 300 --rate 100 --duration 5m --access-rate 40   # traffic for the dashboards
```

## Dashboards

`deploy/monitoring/grafana/dashboards` holds five Grafana dashboards that link to each other and share the variables
data source, namespace (Kubernetes), member and gateway:

| Dashboard | Shows |
|---|---|
| **radiusward · overview** | one screen: leader, members reporting, gateways connected, Accounting-Responses and Access-Accepts per second, reject ratio, export lag, lowest disk, first certificate expiry, top reject causes, firing alerts |
| **accounting and cluster** | events, gateway packets, pending commits, problems, sessions, leader and elections, snapshots, state version, log on disk and purge floor, export lag, rows, batches, errors and the exporting member |
| **authentication** | Access-Requests by result, drops, reject causes, workers in flight, EAP outcomes and success ratio by method, TLS resumptions, certificate expiry, identity store look-ups and latency (p50/p95/p99), verifiers, Simultaneous-Use, SIM sequence numbers, CoA, authentication log |
| **transports and proxying** | RadSec, DTLS and TCP, dynamic NAS entries, proxied requests and home servers alive, inner-tunnel proxying, CoA relay |
| **resources** | heap, direct memory, GC, threads, uptime, dropped log messages; on Kubernetes container memory against the limit and CPU throttling (cAdvisor, kube-state-metrics) |

Panels of features that are not configured stay empty. Grafana provisions them from the directory (compose mounts it;
any Grafana can import the JSON files). `MonitoringConfigTest` checks that every metric they and the alert rules use
is exported and every exported metric is documented below.

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
| `radiusward_gateway_access_requests_total{result}` | counter | Access-Requests: `received`, `status_server`, `accepted`, `rejected`, `challenged`, `dropped`, `cache_hits`, `retransmit_in_flight`, `busy`, `message_authenticator_missing`, `message_authenticator_failed`, `handler_errors`, `unknown_nas`, … (with `gateway.auth.enabled`) |
| `radiusward_gateway_access_in_flight` / `radiusward_gateway_access_reply_cache_entries` | gauge | Access-Requests with the workers; replies kept for retransmissions |
| `radiusward_gateway_access_rejects_total{cause}` | counter | Access-Rejects by the cause the handler recorded (`user not in any store`, `outside Login-Time`, `Simultaneous-Use not granted`, …; `credentials or method rejected` when none was recorded); a fixed set of causes |
| `radiusward_gateway_eap_total{method,outcome}` | counter | EAP conversations by the outer method (`tls`, `peap`, `ttls`, `teap`, `pwd`, `sim`, `aka`, `aka-prime`, `md5`) and how the method ended: `succeeded` (authorization follows), `failed`, `too_many_rounds`, `store_unavailable` |
| `radiusward_gateway_store_lookups_total{store,result}` | counter | identity store look-ups that reached the store (cache hits excluded): `found`, `not_found`, `unavailable` |
| `radiusward_gateway_store_lookup_seconds{store}` | histogram | how long those look-ups took (0.5 ms to 2.5 s buckets) |
| `radiusward_gateway_sim_sqn_requests_total{outcome}` | counter | SIM sequence numbers asked of the cluster for EAP-AKA/AKA′: `ok`, `unsupported` (state version 8 not active), `capacity` (`service.sim.subscribers.max` reached), `unavailable` (no answer in time) |
| `radiusward_tls_certificate_expiry_timestamp_seconds{use}` | gauge | when the server certificate in use expires (Unix time): `eap`, `radsec` (RadSec and DTLS); follows reloads |
| `radiusward_gateway_eap_tls_reloads_total{result}` / `radiusward_gateway_radsec_tls_reloads_total{result}` | counter | changes of the EAP or RadSec certificate, key, CA or CRL files: `loaded`, or `failed` (the previous ones kept) |
| `radiusward_gateway_eap_tls_resumptions_total` | counter | EAP TLS handshakes that resumed an earlier session (PEAP and TTLS skip their inner method) |
| `radiusward_gateway_radsec_total{result}` / `radiusward_gateway_dtls_total{result}` / `radiusward_gateway_tcp_total{result}` | counter | RadSec, DTLS and plain TCP connections and packets: `connections_accepted`, `connections_refused`, `handshakes_failed`, `handshakes_resumed`, `nas_refused`, `requests`, `malformed`, `replies`, `dropped`, `timed_out`, `coa_sent`, `coa_answers`, … |
| `radiusward_gateway_radsec_connections` / `radiusward_gateway_dtls_associations` | gauge | open RadSec connections and DTLS associations |
| `radiusward_gateway_nas_dynamic_total{result}` / `radiusward_gateway_nas_dynamic_entries` | counter / gauge | NAS entries looked up on demand (`nas.dynamic.*`): `lookups`, `found`, `not_found`, `failed`, `queue_full`, `expired`; entries loaded |
| `radiusward_gateway_proxy_requests_total{home,result}` | counter | Access-Requests proxied to a home server (ADR 0037): `requests`, `accepted`, `rejected`, `challenged`, `resent`, `timeouts`, `invalid` |
| `radiusward_gateway_proxy_home_alive{home}` | gauge | 1 while a home server answers, 0 while it is marked dead |
| `radiusward_gateway_inner_proxy_total{result}` | counter | inner-tunnel credentials checked by the home servers of their realms: `requests`, `accepted`, `rejected`, `no_answer` |
| `radiusward_gateway_coa_requests_total{result}` | counter | CoA and Disconnect-Requests to NAS (RFC 5176): `sent`, `resent`, `ack`, `nak`, `timeout`, `unreachable`, `invalid_responses` |
| `radiusward_gateway_coa_relay_total{result}` | counter | CoA and Disconnect-Requests from home servers, relayed: `received`, `unknown_sender`, `bad_authenticator`, `malformed`, `duplicate`, `ack`, `nak`, `no_session`, `no_answer` |
| `radiusward_gateway_simultaneous_use_disconnects_total{result}` | counter | oldest sessions disconnected for a new one (`coa.simultaneous.use = disconnect-oldest`): `acknowledged`, `failed` |
| `radiusward_gateway_store_sweep_total{result}` | counter | store sweeps (ADR 0036): `sweeps`, `users` looked up again, `disconnected`, `changed`, `unavailable` |
| `radiusward_gateway_auth_log_entries_total{result}` | counter | authentication log entries (ADR 0058): `written`, `dropped` (queue full), `failed` |
| `radiusward_gateway_verifier_events_total{verifier,event}` | counter | credential verifiers (ADR 0025): `accepted`, `rejected`, `unavailable`; Netlogon also `channels_opened`, `server_failures` — rising `unavailable` means the directory or domain controllers cannot be reached |
| `radiusward_gateway_access_reply_items_filtered_total{nas}` | counter | vendor attributes left out of Access-Accepts because the NAS entry is of another vendor (`nas.<name>.reply.vendors`) — expected for mixed-vendor groups; a NAS missing an attribute shows here |
| `radiusward_gateway_packets_total{result}` | counter | `received`, `committed`, `cache_hits`, `duplicates`, `stale`, `rejected`, `pending_full`, `ring_full`, `resubmitted`, `resubmitted_on_new_leader`, `malformed`, `unknown_nas`, `authenticator_failed`, `identity_missing`, `identity_fallback`, `status_server`, `status_server_ignored` (Status-Server on the accounting port, ADR 0024), … (all gateway counters) |
| `radiusward_gateway_pending_requests` | gauge | requests waiting for a commit |
| `radiusward_gateway_response_cache_entries` | gauge | RFC 5080 response cache size |
| `radiusward_gateway_cluster_connected` | gauge | 1 while connected to the cluster |

### Every process

`radiusward_jvm_memory_used_bytes{area}`, `radiusward_jvm_memory_committed_bytes{area}`,
`radiusward_jvm_memory_max_bytes`, `radiusward_jvm_gc_collections_total{gc}`,
`radiusward_jvm_gc_pause_seconds_total{gc}`, `radiusward_jvm_buffer_used_bytes{pool}` (direct memory), `radiusward_jvm_threads`, `radiusward_process_uptime_seconds`,
`radiusward_log_messages_dropped_total` (logging ring full; the caller never blocks).

## Tracing one user or NAS

To see why a request is rejected, trace it ([ADR 0052](../adr/0052-request-traces.md)). With `trace.api.token` set
on the gateway:

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:9190/trace?user=alice&for=10m"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9190/trace          # conditions in force
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9190/trace
```

Each matching Access-Request then appears once in the log (logger `io.radiusward.trace`):

```
trace: Access-Request id 17 from NAS edge-1 -> Access-Reject in 412 µs
  request: User-Name = alice, User-Password = <16 bytes>, NAS-IP-Address = 10.0.0.1, ...
  user found in store main
  group applies: staff
  outside Login-Time Wk0800-1700
```

`nas=<entry>` and `station=<Calling-Station-Id>` work the same; `trace.users`, `trace.nas` and `trace.stations` set
conditions that last. Passwords, keys and EAP payloads are shown only as their length.

Every decision, not only traced ones, can also be kept: `auth.log.dir` and/or `auth.log.sql.url`
([ADR 0058](../adr/0058-authentication-log.md)) write each accept and reject with its cause.

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
