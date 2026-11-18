# ADR 0067: The NAS-facing process is the RADIUS server

Status: Accepted (2026-11-18). Renames what [ADR 0011](0011-gateway-pipeline.md) and
[ADR 0062](0062-members-and-gateways-on-kubernetes.md) called the gateway.

## Context
The process that owns the RADIUS sockets, authenticates and answers NAS devices and hands accounting to the cluster
was called the gateway. RADIUS has no such role: a NAS is configured with RADIUS servers, and the people who run
radiusward look for the RADIUS server in the documentation, the configuration and the dashboards. "Gateway" read
like a further component in front of it, or like the NAS itself (a hotspot gateway, a VPN gateway).

## Decision
- The process is the **RADIUS server**; in names, where the context is clear, **server**. The cluster and its
  members keep their names.
- Everything follows, before the first release and without aliases: the subcommand `radiusward server`, the keys
  `server.*` and variables `RADIUSWARD_SERVER_*`, the metrics `radiusward_server_*` and their label `server`, the Helm
  values `server.*` and resources `<release>-server-<n>`, the compose services `server-a`/`server-b`, the systemd unit
  `radiusward-server`, the admin option `--server`, the module `server` and the package `io.radiusward.server`.
- The SBE field `gatewayId` is `serverId`; the wire format does not change. The PostgreSQL column `gateway_id` is
  `server_id` (schema version 4 renames it), the file sink writes `server_id`.
- ADR file names stay, so published links keep working; their text says RADIUS server.

## Consequences
- Configurations, dashboards, alerts and scripts written for the gateway need the new names; there was no release
  that promised the old ones.
- Benchmark results published before the rename still name their containers `gateway-*`; the benchmark pages read
  both.
