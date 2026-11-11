# Phase 4 plan: Kubernetes, bare metal, backup and operations

Status: **done** (2026-11-11) · [Report](#phase-4-report) · ADRs [0062](../adr/0062-members-and-gateways-on-kubernetes.md), [0063](../adr/0063-seeding-a-replaced-member.md), [0065](../adr/0065-cluster-backup.md)
[Phase 3](phase-3.md) (exporter, metrics), [Phase 5](phase-5-auth.md) (authentication) · Roadmap: [roadmap.md](roadmap.md)

## Goal

An operator installs a production radiusward with one Helm command on Kubernetes, or with systemd units on three
machines, and keeps it running: upgrades without lost accounting, a lost disk or node replaced from a runbook, the
whole cluster restored from a backup, and dashboards and alerts from the first day. Nothing in the accounting
contract changes: an Accounting-Response is still sent only after the commit on a majority.

## Exit criteria

1. **Install:** `helm install` on a three-node cluster gives three members and two gateways; a NAS outside the cluster
   gets Accounting-Responses and Access-Accepts from its real source address (the NAS registry sees the NAS, not a
   node).
2. **Leader pod deleted** under load: no acknowledged record lost, no duplicate exported; the gap stays within the
   NAS retransmission budget (measured, like Phase 2's `FailoverTimingIT`).
3. **Rolling upgrade** of members and gateways under load (`helm upgrade` to a new image): nothing lost, at most one
   election, EAP conversations on a restarted gateway restart cleanly.
4. **Node drain** respects the PodDisruptionBudget: never two members down at once.
5. **Lost disk:** a member whose PersistentVolume is deleted rejoins empty and catches up, by runbook.
6. **Lost quorum / lost cluster:** restored from the backup's snapshot and log to the last backed-up position, by
   runbook; what an operator loses is stated.
7. **Bare metal:** the systemd units run the same three-member cluster on three VMs with the same results for 2 and 3
   (tested in containers with systemd).
8. **Operations:** Prometheus scrapes every pod (plain annotations or a ServiceMonitor); five Grafana dashboards
   (overview, accounting and cluster, authentication, transports and proxying, resources) and alerts for
   authentication as well as accounting ship with the chart and with compose, and an operator can tell from the
   overview alone whether NAS are being answered.

## Proposed decisions

| # | Question | Proposal | Why |
|---|---|---|---|
| 1 | How members find each other when a pod's IP changes on restart | StatefulSet pod DNS names (`radiusward-node-0.radiusward-node…`) in `cluster.members`, Aeron's re-resolution of endpoint names — **proved in 4.1** (ADR 0062); a member waits for its own name before it starts | static membership stays; the names are stable, the IPs are not |
| 2 | How NAS packets reach gateways with their source address | **one LoadBalancer Service per gateway** (cloud NLB, MetalLB on bare metal) with `externalTrafficPolicy: Local`, NAS devices configured with two gateways as primary and secondary (ADR 0062: a node loss cost nothing this way, 7.6 % of requests with one shared Service); a shared Service with `sessionAffinity: ClientIP` for small setups; alternative: gateways with `hostNetwork` on edge nodes | NAS secrets are looked up by source address; multi-round EAP state lives in one gateway, so a NAS must stay on it |
| 3 | Source address of packets a gateway sends (CoA, proxying, RadSec to home servers) | documented: they leave with the node's address (SNAT); NAS and home servers allow the nodes' addresses, or use the `hostNetwork` mode for a fixed one | Kubernetes has no portable egress IP; no extra controller required |
| 4 | Leader heartbeat timeout | `1.5s`, as everywhere (ADR 0062 withdrew Phase 2's 2.5 s for Kubernetes), configurable | measured on kind: 1.5 s replaced a dead leader without NAS retransmissions, 2.5 s caused them |
| 5 | Upgrade order | StatefulSet `RollingUpdate`, readiness = `/ready`, extended from "leader known" to "caught up with the commit position", so the next pod waits until the restarted one is a full member again (ADR 0062: without it a rolling restart lost 14 % of acknowledgements); one election when the leader's pod restarts | Aeron has no leadership transfer; one election is within the retransmission budget; state versions activate on their own (ADR 0005) |
| 6 | Storage | one PVC per member (default 100 Gi), a storage class that honours fsync; local volumes recommended, network block storage supported with higher commit latency | the commit path is an fsync on a majority |
| 7 | Memory limits | limit = heap + direct + `/dev/shm` (emptyDir `Memory` counts against the pod) + 15 %; the image's `small`/`standard`/`large` profiles as chart presets | an emptyDir in memory is charged to the container; the OOM killer must never hit a member |
| 8 | Backup | a `cluster-backup` pod running Aeron's `ClusterBackup` into its own PVC (snapshots and log), plus a CronJob copying it to object storage with a plain `rclone`/`aws` image (optional) | survives losing every member; no new runtime dependency in radiusward |
| 9 | Configuration on Kubernetes | properties in a ConfigMap, NAS secrets, database passwords and TLS keys in Secrets (cert-manager optional); a checksum annotation restarts gateways when they change | the image already reads files and `RADIUSWARD_*`; restarts of stateless gateways are cheap |
| 10 | Kubernetes tests | `scripts/k8s-tests.sh` with [kind](https://kind.sigs.k8s.io/), the chart and radclient load in a pod, **nightly in CI** like `-Plinux`; `helm lint` + `kubeconform` in every CI run | Docker stays optional for development; the chart is checked on every change |
| 11 | Chart distribution | OCI chart `oci://ghcr.io/radiusward/charts/radiusward`, versioned with the image by the release workflow | same registry, same provenance |

## Design

### Chart layout (`deploy/helm/radiusward`)

- **Members:** StatefulSet of 3 (`podManagementPolicy: Parallel`, so a cold start does not wait member by member),
  headless Service for Aeron (UDP ports of consensus, log, catch-up, archive) and the management port, with
  `publishNotReadyAddresses: true` (members must resolve each other before any of them is ready); PVC template;
  `/dev/shm` emptyDir `Memory` with `sizeLimit`; required pod anti-affinity by hostname (zone spread optional);
  PDB `maxUnavailable: 1`; `terminationGracePeriodSeconds` long enough for a clean shutdown; probes: liveness
  `/health`, readiness `/ready`, startup probe for long log replays.
- **Gateways:** StatefulSet without volumes (default 2, spread over nodes; `gateway.id` from the pod index), or a
  DaemonSet in `hostNetwork` mode; a UDP Service per gateway (and optionally a shared one) for 1812/1813 and 3799,
  TCP for RadSec 2083 (DTLS on UDP 2083); `gateway.egress.host` = the pod IP from the downward API; PDB
  `minAvailable: 1`; readiness turns false on SIGTERM so the load balancer stops sending, then the gateway drains
  for a few seconds before it exits.
- **Exporter:** inside the members as today; sink settings and the database Secret come from values.
- **Backup:** optional Deployment of one `cluster-backup` pod with its own PVC; optional CronJob for off-site copies.
- **Security:** non-root (as the image), `readOnlyRootFilesystem`, all capabilities dropped, `seccompProfile:
  RuntimeDefault`; NetworkPolicy: Aeron ports only between members and from gateways, management port from the
  monitoring namespace, RADIUS ports from anywhere (or a list of NAS networks).
- **Monitoring:** `prometheus.io/*` annotations by default; `ServiceMonitor`, `PrometheusRule` (`alerts.yml`) and
  the Grafana dashboards as ConfigMaps when the Prometheus Operator / Grafana sidecar is present (see Dashboards).
- **Values presets:** `small` (1 GiB members, 500k sessions), `standard`, `large`, matching ADR 0004.

### Dashboards (`deploy/monitoring/grafana/dashboards`)

The Phase 3 dashboard has eight accounting panels and divides by a fixed member count of 3; the authentication,
transport and proxy metrics of Phase 5 are exported but shown nowhere. Phase 4 replaces it with a set that shares
variables (`namespace`, `member`, `gateway`, data source) and links to each other:

| Dashboard | Shows |
|---|---|
| **Overview** | one screen: leader known, members ready, gateways connected, Accounting-Responses/s, Access-Accepts and Rejects/s, reject ratio, export lag, disk free, firing alerts |
| **Accounting and cluster** | events by outcome, sessions, response cache, pending commits, egress drops, leader and elections, snapshots, log on disk and purge floor, state version, export rows/batches/errors/lag per sink |
| **Authentication** | Access-Requests by result, in flight vs workers, busy drops, reject causes, per EAP method (TLS, PEAP, TTLS, TEAP, pwd, SIM, AKA, AKA′), TLS resumptions, store and verifier results and latency, Simultaneous-Use disconnects, SIM sequence-number results, CoA/Disconnect, authentication log |
| **Transports and proxying** | RadSec, DTLS and TCP connections and results, dynamic NAS, proxied requests by realm and result, home servers alive, inner proxying, CoA relay |
| **Resources** | heap, direct memory and `/dev/shm` against the pod limit, GC pauses, threads, dropped log messages, CPU throttling (cAdvisor on Kubernetes) |

New metrics the dashboards need (gateway code): a `method` label on EAP results, store and verifier latency as a
histogram, reject causes, SIM sequence-number results, and the expiry of every configured TLS certificate
(`radiusward_tls_certificate_expiry_seconds`). New alerts: reject ratio jump, identity store unavailable, workers
saturated, home server down, certificate expiring within 14 days, SIM sequence-number capacity.

The same dashboards and alerts ship with compose (`--profile monitoring`, Prometheus and Grafana in Docker) and the
chart, and `MonitoringConfigIT` checks that every expression names a metric that is exported. So that the
authentication dashboards show something in Docker, the compose gateways get authentication with a demo users file,
and `radclient` gets an `auth` command and an Access-Request mix in `load` (PAP, CHAP, MS-CHAPv2,
rejects) — today it sends accounting only.

### Node prerequisites

Aeron wants larger UDP socket buffers than most kernels allow (`net.core.rmem_max`, `wmem_max`). These sysctls are
not namespaced, so the chart cannot set them for a pod: the operations guide lists them for the node (or a
privileged DaemonSet the operator chooses to run). The members log a warning when the buffers are clamped.

### Shutdown and restart

- Members: SIGTERM → the consensus module and archive close in order; a member that comes back with its volume
  replays from its last snapshot. A deleted pod of the leader means one election.
- Gateways: SIGTERM → not ready → drain (pending commits answered, EAP conversations abandoned, the NAS retries) →
  exit. Fast re-authentication identities of SIM/AKA kept on that gateway are lost; the peers authenticate in full.

### Bare metal (`deploy/systemd`)

Units `radiusward-node@.service` and `radiusward-gateway.service`, an environment file per host
(`/etc/radiusward/radiusward.env`), a `tmpfs` for the Aeron directory sized like the container's `/dev/shm`,
`LimitNOFILE`, the sysctls above in `/etc/sysctl.d/`, `Restart=on-failure`, hardening (`ProtectSystem=strict`,
`NoNewPrivileges`, a dedicated user). The same runnable jar and JVM flags as the image's entrypoint.

### Backup and recovery runbooks (`docs/operations/`)

- **Replace a member** (lost disk or node): an empty member cannot catch up once the log below the snapshot is purged
  (checked in 4.1, ADR 0062), so it seeds itself before it starts: Aeron ClusterBackup copies the latest snapshot and
  the log after it from the other members into its new volume, then it joins and catches up the rest (done, ADR 0063).
- **Lost quorum** (two members gone): every member restored from the continuous backup with `cluster-restore`
  (`scripts/k8s-restore.sh` on Kubernetes); what is lost is the backup's lag, `radiusward_backup_*` metrics (done, ADR 0065).
- **Upgrades and rollback:** state versions only move forward once activated; rolling back to an image older than
  the active state version is refused, which the runbook says before an upgrade.

## Work packages

| # | Package | Content | Size |
|---|---|---|---|
| 4.1 ✅ | Spike: members on Kubernetes ([ADR 0062](../adr/0062-members-and-gateways-on-kubernetes.md)) | kind cluster, three members by DNS name, pods deleted and rescheduled with new IPs, re-resolution settings; empty member catching up after log purge. Decides decisions 1 and the member-replacement runbook | M |
| 4.2 ✅ | Helm chart: members | code done 2026-11-11: `/ready` false while the election is open, a member waits for its own name, a 1 s JVM name cache (ADR 0062); chart: StatefulSet, Services, PVCs, shm, probes, anti-affinity, PDB, presets, ConfigMap/Secrets, NetworkPolicy, security context | M |
| 4.3 ✅ | Helm chart: gateways (drain on SIGTERM still open) | StatefulSet and `hostNetwork` modes, a UDP/TCP Service per gateway (and a shared one) with source-IP preservation, downward API egress host, drain on SIGTERM (code: readiness off on shutdown) | M |
| 4.4 ✅ | Chart checks in CI | `helm lint` and `kubeconform` (Kubernetes 1.31 and 1.35, Prometheus Operator CRDs) with the defaults and `ci/all-on-values.yaml`; OCI chart in the release workflow | S |
| 4.5 ✅ | Kubernetes tests (nightly: `scripts/k8s-tests.sh`, `k8s-tests.yml`) | kind + Testcontainers: install, accounting and EAP through the LoadBalancer (MetalLB in kind), leader pod deleted under load, rolling upgrade, node drain with the PDB, member replacement | L |
| 4.6 ✅ | Backup (seeding a replaced member, [ADR 0063](../adr/0063-seeding-a-replaced-member.md); continuous backup outside the cluster and restore after a lost quorum, [ADR 0065](../adr/0065-cluster-backup.md)) | `cluster-backup` subcommand around Aeron `ClusterBackup`, backup lag metric, chart pod and optional CronJob; restore with `cluster-tool`; tests for backup and restore | M |
| 4.7 ✅ | systemd | units for members and gateways (`deploy/systemd`, hardened, verified with `systemd-analyze`), env file, sysctls; [bare-metal.md](../operations/bare-metal.md); `SystemdFailoverIT` in the `linux-tests` runs them with systemd as PID 1 under load (kill → restart, stop/start, reload, drain) and found the missing `SuccessExitStatus=143` | S |
| 4.8 ✅ | Dashboards and alerts (the chart's ServiceMonitor, PrometheusRule and ConfigMaps follow with 4.2) | compose gateways with authentication, `radclient auth` and an Access-Request load mix; the five dashboards above, the missing metrics (EAP method, latency histograms, reject causes, SQN, certificate expiry), authentication alerts, ServiceMonitor/PodMonitor, PrometheusRule, dashboard ConfigMaps; `MonitoringConfigIT` extended | M |
| 4.9 ✅ | Load and chaos on Kubernetes (`scripts/k8s-tests.sh scale`) | 500k sessions and the authentication mix through the LoadBalancer; pod kill, network partition (NetworkPolicy), node drain during load; results in the report | M |
| 4.10 ✅ | Documentation | `docs/operations/kubernetes.md`, `bare-metal.md`, `backup.md`, runbooks; ADRs for decisions 1, 2, 8 | S |

## Order

4.8 first (decided 2026-11-11): the dashboards need no Kubernetes and serve compose and the Phase 5 features at once.
Then 4.1: it decides how members are addressed and how a member is replaced. Then 4.2 → 4.3 → 4.4 (a usable
chart), 4.5 (proof), 4.6 (backup), 4.7, 4.8, 4.9 and 4.10 alongside. The first release candidate can be tagged after
4.5.

## Risks

- **Re-resolution:** settled in 4.1 — members rejoin by name after their pods move (ADR 0062).
- **Load balancers differ:** source-IP preservation and UDP affinity behave differently across clouds and MetalLB
  modes. The tests use ClusterIP Services on kind (one per gateway); real LoadBalancers are not tested yet (open).
- **fsync on network storage:** commit latency rises with the volume's fsync time; the guide gives the measured
  numbers and recommends local volumes.
- **Election on pod pauses:** CPU throttling or long GC in a pod can look like a dead leader; members get guaranteed
  CPU (requests = limits) in the presets.
- **Gateway restarts drop EAP state:** each restart makes the peers in the middle of EAP start again; affinity keeps
  it to restarts, not every packet.

## Phase 4 report

Done 2026-11-11: radiusward installs with one Helm command or with systemd units, survives the loss of a member, a
node and a whole quorum, and publishes what its tests prove. Everything below was measured on kind (Kubernetes 1.37,
three workers, the `small` profile) on a laptop, and runs again nightly on GitHub's runners.

| Exit criterion | Result |
|---|---|
| 1. Install | `helm install` gives three members, two gateways and the backup; accounting and Access-Requests from a pod through both gateways, NAS entries matched by source address |
| 2. Leader pod deleted under load | nothing lost; with a 1.5 s heartbeat no retransmission, max 2.3 s (ADR 0062; 2.5 s caused retransmissions) |
| 3. Rolling upgrade | members: nothing lost and no retransmission in 8 of 8 runs once the JVM's name cache was cut to 1 s (it had made 2 of 5 runs lose acknowledgements); gateways: nothing lost, requests in flight retried once through the other gateway (max 3 s) |
| 4. Node drain | the members' PodDisruptionBudget held a drain back while a member was still catching up (never two members down); nothing lost |
| 5. Lost disk | the member seeds itself from the others (ADR 0063): 3.6–4 s, ready 10 s after its pod started, under load, nothing lost or retried |
| 6. Lost quorum | restored from the continuous backup with `scripts/k8s-restore.sh` (ADR 0065): 4000 events, 1500 of them after the snapshot, back on all three members; the same in compose and in `ClusterBackupIT` |
| 7. Bare metal | `SystemdFailoverIT` with systemd as PID 1: killed member restarted, stop/start, reload and drain, nothing lost; found `SuccessExitStatus=143` missing |
| 8. Operations | five Grafana dashboards, 19 alerts, PodMonitor, PrometheusRule and dashboard ConfigMaps in the chart; Allure test reports on GitHub Pages (ADR 0064) |

**Scale and chaos (4.9):** 500,000 sessions and 84,000 Access-Requests through both gateways from two load pods in
420 s (about 1,760 requests/s, the laptop's load generators' limit), while the leader was killed, a follower cut off by
a NetworkPolicy for 30 s and a worker drained: 739,319 accounting requests acknowledged, **none failed and none
retransmitted** (max 2.3 s), no Access-Request lost or answered wrongly, 500,000 active sessions on all three members
at the same log position, no container restarted or out of memory.

**Found and fixed on the way:** the JVM's 30 s name cache (elections stuck for ~20 s after a rolling restart), a member
crashing before its own DNS record existed, readiness true before a restarted member caught up, an empty member unable
to catch up after a purge, a seeded log recording short of the current term, readiness of members started from a
snapshot, the systemd exit status, a restore from a read-only backup and from a copy that went through macOS, local
volumes placed on the wrong node during a restore, and the backup's readiness holding back `helm install --wait`.

**Open:** real LoadBalancers (cloud, MetalLB) in the tests; a node drain that runs to completion in the scale
scenario; load beyond what a laptop generates (Phase 4 measured correctness, not the throughput limit).

