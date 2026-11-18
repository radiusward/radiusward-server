# Kubernetes

The Helm chart in [`deploy/helm/radiusward`](../../deploy/helm/radiusward) runs three cluster members and RADIUS
RADIUS servers. Its design and the measurements behind it: [ADR 0062](../adr/0062-members-and-gateways-on-kubernetes.md),
[Phase 4 plan](../plans/phase-4.md).

## Install

```bash
helm install radiusward oci://ghcr.io/radiusward/charts/radiusward --version 0.1.0-rc.1 \
     -n radius --create-namespace -f my-values.yaml          # a released chart (docs/operations/release.md)
helm install radiusward deploy/helm/radiusward -n radius --create-namespace -f my-values.yaml   # from a checkout
kubectl -n radius get pods -l app.kubernetes.io/instance=radiusward
kubectl -n radius exec radiusward-node-0 -- radiusward probe http://127.0.0.1:9090/ready
```

Every release tag publishes the chart (first: `0.1.0-rc.1`); a checkout installs the state of `main`.

A minimal `my-values.yaml`:

```yaml
profile: small                      # small | standard | large (ADR 0004)
node:
  persistence: {size: 100Gi, storageClass: local-ssd}
  export:
    postgres: {enabled: true, url: "jdbc:postgresql://postgres:5432/radius", existingSecret: radius-db}
server:
  nas:
    - {name: branch-routers, address: 10.20.0.0/16, existingSecret: nas-secrets, existingSecretKey: branch, vendor: cisco}
  auth:
    enabled: true
    stores:
      - {name: db, type: sql, url: "jdbc:postgresql://postgres:5432/radius", user: radius, existingSecret: radius-db}
    eap:
      methods: [peap, ttls]
      tls: {existingSecret: radius-eap-tls}     # kubernetes.io/tls Secret, plus ca.crt for EAP-TLS
```

## What the chart creates

| Object | Purpose |
|---|---|
| StatefulSet `<release>-node` (3 pods) | the members; `cluster.node.id` is the pod index, members find each other by DNS name; one volume each |
| Service `<release>-node` (headless) | the members' DNS names, published before they are ready (none is ready without a quorum) |
| StatefulSet `<release>-server` (default 2) | the RADIUS servers; `server.id` is the pod index, `server.egress.host` the pod IP; no volumes |
| Service `<release>-server-<n>` per RADIUS server | its address for the NAS devices (LoadBalancer, `externalTrafficPolicy: Local`) |
| Service `<release>-servers` (optional) | one address for all RADIUS servers, `sessionAffinity: ClientIP` |
| PodDisruptionBudgets | members `maxUnavailable: 1`, RADIUS servers `minAvailable: 1` |
| ConfigMaps, Secret | `cluster.properties` and `server.properties`; passwords and users files given in values |
| NetworkPolicies (optional) | Aeron only between members and RADIUS servers; RADIUS from `networkPolicy.radiusClientCIDRs` |
| PodMonitor, PrometheusRule, dashboard ConfigMaps (optional) | the alerts and Grafana dashboards of [monitoring.md](monitoring.md) |

Every key of [configuration.md](../configuration.md) is reachable through `node.config` and `server.config` (added
to the properties files last, so they win). Secrets never go into the ConfigMaps: NAS secrets and store passwords
are passed as environment variables from Secrets and referenced as `${env:...}`; users files and certificates are
mounted from Secrets. A change of the RADIUS servers' configuration or Secret restarts them one at a time; a change of the
members' configuration rolls the members.

| Value | Default | Meaning |
|---|---|---|
| `profile` | `small` | JVM sizes and resources: members 1 CPU / 1.5 Gi (`small`), 2 / 4 Gi, 4 / 11 Gi; RADIUS servers 1 / 768 Mi, 2 / 1.25 Gi, 4 / 2.25 Gi. Requests equal limits |
| `node.persistence.size` / `.storageClass` | `100Gi` / default | one volume per member |
| `node.leaderHeartbeatTimeout` | `1500ms` | measured on Kubernetes without NAS retransmissions (ADR 0062) |
| `node.antiAffinity`, `server.antiAffinity` | `hard` | one member (server) per node; `soft` or `none` for small test clusters |
| `node.zoneSpread` | `false` | also spread members over zones |
| `node.export.postgres.*` | off | the PostgreSQL sink; password from `existingSecret` or `password` |
| `server.nas[]` | — | `name`, `address` (address or CIDR), `secret` or `existingSecret`/`existingSecretKey`, `vendor`, `id` |
| `server.auth.stores[]` | — | `file` (`users` or a Secret with the users file), `sql` (`url`, `user`, password Secret); `chap`, `mschap` |
| `server.auth.eap.methods`, `.tls.existingSecret` | — | EAP methods and the server certificate Secret (`tls.crt`, `tls.key`, `ca.crt`) |
| `server.radsec.enabled`, `.existingSecret` | off | RadSec on 2083/tcp with that certificate Secret |
| `server.coa.enabled` | off | CoA and Disconnect (3799/udp) |
| `server.service.type` / `.perServer` | `LoadBalancer` / — | per-server Service type; fixed addresses per pod index (`loadBalancerIP`, annotations) |
| `server.minReadySeconds` | `10` | a restarted RADIUS server serves this long before the next one restarts |
| `metrics.*` | annotations on | `prometheus.io/*` annotations; PodMonitor, PrometheusRule and dashboards for the Prometheus Operator and Grafana sidecar |

## NAS configuration: two RADIUS servers

Configure every NAS with two radiusward RADIUS servers as its primary and secondary server (authentication and accounting).
When a node fails, the NAS retries through the other RADIUS server and the cluster recognises the retry as the same
request. With a single shared address, Kubernetes keeps sending part of the traffic to the failed node's RADIUS server
until it marks the node NotReady (about 40–50 s); in the spike that lost 7.6 % of the accounting, two addresses lost
nothing.

NAS entries are matched by the packets' source address, so the RADIUS servers must see it: `externalTrafficPolicy: Local`
(the chart's default) on cloud load balancers and MetalLB, or RADIUS servers on edge nodes with host networking. CoA,
Disconnect and proxied requests leave with the node's address; NAS devices and home servers must accept those.

## Nodes

- **UDP buffers.** Aeron wants larger socket buffers than most kernels allow; these sysctls are not namespaced, so
  set them on the nodes (or with a privileged DaemonSet you choose to run):

  ```bash
  sysctl -w net.core.rmem_max=2097152 net.core.wmem_max=2097152
  ```

- **Storage.** Every Accounting-Response waits for an fsync on a majority of members: use a storage class whose
  volumes honour fsync and answer quickly — local volumes (local-path, TopoLVM, OpenEBS LocalPV) are best; network
  block storage works with higher latency. Size: the log between snapshots and purges plus two snapshots
  (100 Gi is ample for 500k sessions).
- **CPU.** Members get guaranteed CPU (requests = limits): a throttled or paused leader looks dead and costs an
  election.

## Replacing a member's volume

Delete the member's claim and pod (`kubectl delete pvc data-<release>-node-1 --wait=false; kubectl delete pod
<release>-node-1`). The new pod finds its volume empty and first copies the latest snapshot and the log after it from
the other members (`node.seedTimeout`, 20 s; [ADR 0063](../adr/0063-seeding-a-replaced-member.md)); on kind this took
4 s under load and the member was ready 10 s after it started. While it is away the other two keep the quorum. The
first install waits `node.seedTimeout` once, as there is nobody to copy from yet.

## Backup and a lost quorum

The chart runs a continuous backup outside the cluster (`backup.enabled`, its own 100 Gi volume,
[ADR 0065](../adr/0065-cluster-backup.md)). After a lost quorum `scripts/k8s-restore.sh -n <namespace> -r <release>`
restores all three members from it; see [backup.md](backup.md).

## Upgrades

`helm upgrade` rolls the members one at a time: a restarted member counts as ready only once its election is
closed, so the next one waits until it has caught up, and the cluster keeps its quorum. Each member restart may
cost one leader election (~2 s with the default timeouts, within a NAS's retransmission time). On kind, rolling all
members under accounting and authentication load lost nothing and caused no retransmission. Rolling the RADIUS servers
lost nothing either, but each RADIUS server's own Service has no other pod behind it: requests a NAS sends to a RADIUS server
while it restarts (a few seconds) are answered only after the NAS's timeout, through its secondary RADIUS server (on kind
about 200 of 5500 requests, max 3 s). `server.shutdownDrain` (5 s) keeps a stopping RADIUS server answering after it
reports not ready, which helps the shared Service and load balancers with health checks; restart RADIUS servers in quiet
hours if NAS timeouts matter.

State-machine changes activate on their own once every member runs the new version
([ADR 0005](../adr/0005-log-determinism-versioning.md)); after that, going back to an image older than the active
state version is refused.

## Tests

`scripts/k8s-tests.sh` builds the image, creates a kind cluster with three workers, installs the chart and runs
accounting and Access-Request load from a pod through both RADIUS servers while it kills the leader, rolls the members,
rolls the RADIUS servers, replaces a member's volume after a purge and restores the whole cluster from the backup after
deleting every member's volume; a lost request fails the run. The RADIUS servers get LoadBalancer addresses from MetalLB
(L2, `externalTrafficPolicy: Local`), and a NAS outside the cluster — a container on kind's network, known to
radiusward only by its own /32 address — sends accounting and Access-Requests through them, so a load balancer
that rewrote the source address would fail the run. It runs nightly in CI (`k8s-tests.yml`, pod logs as an
artifact) and takes about 25 minutes; `KEEP=1` keeps the cluster, and scenario names (`baseline loadbalancer
leader-kill member-roll server-roll replace-volume restore-quorum`) run a subset. `scripts/k8s-tests.sh scale` (opt-in, ~10 min)
puts 500k sessions and Access-Requests through both RADIUS servers while it kills the leader, cuts a member off with a
NetworkPolicy and drains a node to completion once every member is ready ([Phase 4 report](../plans/phase-4.md#phase-4-report)).
