# Kubernetes

The Helm chart in [`deploy/helm/radiusward`](../../deploy/helm/radiusward) runs three cluster members and RADIUS
gateways. Its design and the measurements behind it: [ADR 0062](../adr/0062-members-and-gateways-on-kubernetes.md),
[Phase 4 plan](../plans/phase-4.md).

## Install

```bash
helm install radiusward oci://ghcr.io/radiusward/charts/radiusward --version 0.1.0 \
     -n radius --create-namespace -f my-values.yaml          # a released chart (docs/operations/release.md)
helm install radiusward deploy/helm/radiusward -n radius --create-namespace -f my-values.yaml   # from a checkout
kubectl -n radius get pods -l app.kubernetes.io/instance=radiusward
kubectl -n radius exec radiusward-node-0 -- radiusward probe http://127.0.0.1:9090/ready
```

A minimal `my-values.yaml`:

```yaml
profile: small                      # small | standard | large (ADR 0004)
node:
  persistence: {size: 100Gi, storageClass: local-ssd}
  export:
    postgres: {enabled: true, url: "jdbc:postgresql://postgres:5432/radius", existingSecret: radius-db}
gateway:
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
| StatefulSet `<release>-gateway` (default 2) | the gateways; `gateway.id` is the pod index, `gateway.egress.host` the pod IP; no volumes |
| Service `<release>-gateway-<n>` per gateway | each gateway's RADIUS address (LoadBalancer, `externalTrafficPolicy: Local`) |
| Service `<release>-gateways` (optional) | one address for all gateways, `sessionAffinity: ClientIP` |
| PodDisruptionBudgets | members `maxUnavailable: 1`, gateways `minAvailable: 1` |
| ConfigMaps, Secret | `cluster.properties` and `gateway.properties`; passwords and users files given in values |
| NetworkPolicies (optional) | Aeron only between members and gateways; RADIUS from `networkPolicy.radiusClientCIDRs` |
| PodMonitor, PrometheusRule, dashboard ConfigMaps (optional) | the alerts and Grafana dashboards of [monitoring.md](monitoring.md) |

Every key of [configuration.md](../configuration.md) is reachable through `node.config` and `gateway.config` (added
to the properties files last, so they win). Secrets never go into the ConfigMaps: NAS secrets and store passwords
are passed as environment variables from Secrets and referenced as `${env:...}`; users files and certificates are
mounted from Secrets. A change of the gateways' configuration or Secret restarts them one at a time; a change of the
members' configuration rolls the members.

| Value | Default | Meaning |
|---|---|---|
| `profile` | `small` | JVM sizes and resources: members 1 CPU / 1.5 Gi (`small`), 2 / 4 Gi, 4 / 11 Gi; gateways 1 / 768 Mi, 2 / 1.25 Gi, 4 / 2.25 Gi. Requests equal limits |
| `node.persistence.size` / `.storageClass` | `100Gi` / default | one volume per member |
| `node.leaderHeartbeatTimeout` | `1500ms` | measured on Kubernetes without NAS retransmissions (ADR 0062) |
| `node.antiAffinity`, `gateway.antiAffinity` | `hard` | one member (gateway) per node; `soft` or `none` for small test clusters |
| `node.zoneSpread` | `false` | also spread members over zones |
| `node.export.postgres.*` | off | the PostgreSQL sink; password from `existingSecret` or `password` |
| `gateway.nas[]` | — | `name`, `address` (address or CIDR), `secret` or `existingSecret`/`existingSecretKey`, `vendor`, `id` |
| `gateway.auth.stores[]` | — | `file` (`users` or a Secret with the users file), `sql` (`url`, `user`, password Secret); `chap`, `mschap` |
| `gateway.auth.eap.methods`, `.tls.existingSecret` | — | EAP methods and the server certificate Secret (`tls.crt`, `tls.key`, `ca.crt`) |
| `gateway.radsec.enabled`, `.existingSecret` | off | RadSec on 2083/tcp with that certificate Secret |
| `gateway.coa.enabled` | off | CoA and Disconnect (3799/udp) |
| `gateway.service.type` / `.perGateway` | `LoadBalancer` / — | per-gateway Service type; fixed addresses per pod index (`loadBalancerIP`, annotations) |
| `gateway.minReadySeconds` | `10` | a restarted gateway serves this long before the next one restarts |
| `metrics.*` | annotations on | `prometheus.io/*` annotations; PodMonitor, PrometheusRule and dashboards for the Prometheus Operator and Grafana sidecar |

## NAS configuration: two gateways

Configure every NAS with two gateways as its primary and secondary RADIUS server (authentication and accounting).
When a node fails, the NAS retries through the other gateway and the cluster recognises the retry as the same
request. With a single shared address, Kubernetes keeps sending part of the traffic to the failed node's gateway
until it marks the node NotReady (about 40–50 s); in the spike that lost 7.6 % of the accounting, two addresses lost
nothing.

NAS entries are matched by the packets' source address, so the gateways must see it: `externalTrafficPolicy: Local`
(the chart's default) on cloud load balancers and MetalLB, or gateways on edge nodes with host networking. CoA,
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

## Upgrades

`helm upgrade` rolls the members one at a time: a restarted member counts as ready only once its election is
closed, so the next one waits until it has caught up, and the cluster keeps its quorum. Each member restart may
cost one leader election (~2 s with the default timeouts, within a NAS's retransmission time). On kind, rolling all
members under accounting and authentication load lost nothing and caused no retransmission. Rolling the gateways
lost nothing either, but each gateway's own Service has no other pod behind it: requests a NAS sends to a gateway
while it restarts (a few seconds) are answered only after the NAS's timeout, through its secondary gateway (on kind
about 200 of 5500 requests, max 3 s). `gateway.shutdownDrain` (5 s) keeps a stopping gateway answering after it
reports not ready, which helps the shared Service and load balancers with health checks; restart gateways in quiet
hours if NAS timeouts matter.

State-machine changes activate on their own once every member runs the new version
([ADR 0005](../adr/0005-log-determinism-versioning.md)); after that, going back to an image older than the active
state version is refused.

## Not yet in the chart

- **A backup outside the cluster** (Phase 4.6, second part): losing two members at once still loses the quorum;
  restoring then needs a snapshot kept elsewhere.
- Gateways do not yet drain on shutdown; a restarting gateway's requests in flight are retried by the NAS.
