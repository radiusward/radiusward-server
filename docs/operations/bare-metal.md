# Bare metal and VMs with systemd

Three cluster members on three machines (or VMs) and two or more gateways, run by systemd. The units in
[`deploy/systemd`](../../deploy/systemd) start the same `radiusward.jar` with the same JVM settings per profile as the
container image ([ADR 0004](../adr/0004-memory-budget.md)). Kubernetes: [kubernetes.md](kubernetes.md).

## Install

On every host (Java 25 on the `PATH`, e.g. the Temurin 25 JRE):

```bash
sudo useradd --system --home-dir /var/lib/radiusward --shell /usr/sbin/nologin radiusward
sudo install -d -o radiusward -g radiusward /var/lib/radiusward
sudo install -d /opt/radiusward /etc/radiusward/dictionary.d
sudo install -m 0644 radiusward.jar /opt/radiusward/radiusward.jar          # from the GitHub release
sudo install -m 0755 deploy/docker/entrypoint.sh /usr/local/bin/radiusward  # picks heap/direct memory per profile
sudo install -m 0644 deploy/systemd/99-radiusward.conf /etc/sysctl.d/ && sudo sysctl --system
sudo install -m 0640 -g radiusward deploy/systemd/radiusward.env /etc/radiusward/radiusward.env
```

Members (one per host):

```bash
sudo install -m 0644 deploy/compose/config/cluster.properties /etc/radiusward/   # then edit, see below
sudo install -m 0644 deploy/systemd/radiusward-node.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now radiusward-node
radiusward probe http://127.0.0.1:9090/ready
```

Gateways:

```bash
sudo install -m 0644 deploy/compose/config/gateway.properties deploy/compose/config/nas-clients.properties /etc/radiusward/
sudo install -m 0644 deploy/systemd/radiusward-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now radiusward-gateway
```

## Configuration

- `cluster.members` lists the three member hosts in member-id order, the same on every member and gateway. Use IP
  addresses or names that always resolve to the same host; members and gateways cache names for 1 s
  ([ADR 0062](../adr/0062-members-and-gateways-on-kubernetes.md)).
- `/etc/radiusward/radiusward.env` sets `RADIUSWARD_CLUSTER_NODE_ID` (members) or `RADIUSWARD_GATEWAY_ID` and
  `RADIUSWARD_GATEWAY_EGRESS_HOST` (gateways), `RADIUSWARD_PROFILE`, and the secrets the properties files reference as
  `${env:...}`. Every key of [configuration.md](../configuration.md) can be set there as `RADIUSWARD_<KEY>`.
- `cluster.seed.timeout=20s` on members lets a member whose disk was replaced copy the latest snapshot from the others
  before it starts ([ADR 0063](../adr/0063-seeding-a-replaced-member.md)).
- Memory: a `small` member needs about 1 GiB for the JVM plus `/dev/shm` for Aeron (512 MiB); `standard` and `large`
  scale as in [docker.md](docker.md). `/dev/shm` is a tmpfs of half the RAM by default, which is enough.
- Disks: the member's data directory needs a file system that honours fsync; local SSDs are recommended.
- Firewall: members talk to each other on `cluster.base.port + 100 × id + 0…5` (UDP); gateways reach the members'
  ingress ports; NAS devices reach the gateways on 1812/1813 UDP (and 2083 TCP for RadSec).

## Operations

- `systemctl stop radiusward-node` closes the member cleanly; stopping one member at a time keeps the quorum. Restart a
  member only once the previous one reports ready (`/ready`).
- `systemctl reload radiusward-gateway` reloads NAS entries, stores and policies (SIGHUP, [ADR 0054](../adr/0054-config-reload.md)).
- Gateways report not ready for 5 s after SIGTERM while still answering (`RADIUSWARD_GATEWAY_SHUTDOWN_DRAIN`), so a
  keepalived or load-balancer health check on `/ready` moves the address first. Configure NAS devices with two
  gateways as primary and secondary servers.
- Logs go to the journal (`journalctl -u radiusward-node`); metrics on the management port (`/metrics`,
  [monitoring.md](monitoring.md)).

The units are hardened (`ProtectSystem=strict`, no capabilities, only the data directory and `/dev/shm` writable);
`systemd-analyze security` rates the member unit 4.5 ("OK").
