# Docker and compose

One image for every component ([ADR 0015](../adr/0015-container-image.md)):
`ghcr.io/radiusward/radiusward-server:<version>` (or `radiusward:dev` built locally). On Kubernetes use the Helm
chart: [kubernetes.md](kubernetes.md); on machines without containers the systemd units: [bare-metal.md](bare-metal.md).

## Build the image locally

```bash
./mvnw -q install -DskipTests                                   # distribution/target/radiusward.jar
docker build -f deploy/docker/Dockerfile -t radiusward:dev .
docker run --rm radiusward:dev version
```

On macOS, [Colima](https://github.com/abiosoft/colima) works (`colima start --cpu 8 --memory 12`); so does
Docker Desktop.

## Compose: 3 members + 2 gateways

```bash
docker compose -f deploy/compose/compose.yaml up -d --wait      # small profile, fsync on
docker compose -f deploy/compose/compose.yaml ps

# one accounting request and one Access-Request from inside the network
docker compose -f deploy/compose/compose.yaml run --rm tools acct \
    --server gateway-a:1813 --secret testing123 --status start --session-id s1
docker compose -f deploy/compose/compose.yaml run --rm tools auth \
    --server gateway-a:1812 --secret testing123 --user alice --password secret --method mschapv2

deploy/compose/demo-failover.sh                                 # load, kill -9 the leader, verify nothing lost
docker compose -f deploy/compose/compose.yaml down -v           # -v also deletes the data volumes
```

| Service | Address | Ports on the host |
|---|---|---|
| `node-0`, `node-1`, `node-2` | 172.28.0.10–12 | management 127.0.0.1:9090–9092 |
| `gateway-a`, `gateway-b` | 172.28.0.20–21 | accounting 1813/udp and 1814/udp, authentication 1812/udp and 1815/udp (demo users in `config/users`: PAP, CHAP, MS-CHAPv2), management 127.0.0.1:9190–9191 |
| `tools` (profile `tools`) | dynamic | — (`radclient` as entrypoint) |

Configuration lives in [deploy/compose/config](../../deploy/compose/config); per-container values
(`cluster.node.id`, `gateway.id`, `gateway.egress.host`, the NAS secret) come from the environment. The NAS
secret defaults to `testing123`; set `NAS_SECRET` for anything else.

### Profiles

```bash
docker compose -f compose.yaml -f compose.standard.yaml up -d    # 2 GiB / 2 CPU members, 768 MiB gateways
docker compose -f compose.yaml -f compose.large.yaml up -d
```

| Profile | Member | Gateway | `/dev/shm` member | Heap member / gateway |
|---|---|---|---|---|
| small (default) | 1 GiB, 1 CPU | 384 MiB | 512 MiB | 384m / 192m |
| standard | 2 GiB, 2 CPU | 768 MiB | 1 GiB | 1g / 384m |
| large | see `compose.large.yaml` | | | 2560m / 768m |

Tools run in the same image with their own heap: `radclient` 512m, `admin` 256m (its verifiers stream an ack log
and keep one event per session), `probe`/`cluster-tool` 64m; `JAVA_OPTS` overrides it.

Measured with the small profile ([ADR 0004](../adr/0004-memory-budget.md)): 2M sessions at ~32k requests/s
stay at ≤ 448 MiB unreclaimable per member and ≤ 321 MiB per gateway.

## Things to know

- **Static IPs, not container names**, in `cluster.members` and `gateway.egress.host`. Aeron re-resolves the
  endpoint of a dead member; resolving a stopped container's name blocks the media driver for seconds
  (measured: 5.4 s elections with names, 0.6 s with addresses).
- **UDP source address on macOS**: Docker Desktop and Colima rewrite the source address of UDP traffic that
  arrives through a published port, so the gateway sees the VM's address instead of the NAS. A NAS simulator
  on the macOS host therefore matches no `nas.*` entry. Run test clients inside the network (`tools`). On a
  Linux host published ports keep the source address. In Kubernetes use `externalTrafficPolicy: Local`.
- **`/dev/shm`** holds the Aeron buffers; `shm_size` must be set (Docker's default is 64 MiB).
- **Data** lives in the named volumes `node-0..2`; `down -v` deletes it. The members need free space above
  `cluster.disk.min.free` (default 1 GiB) or they report not ready; a full disk stops a member.
- **fsync**: keep `archive.file.sync.level=2`. Anything lower can lose acknowledged events on power loss
  (measured, `PowerLossIT`).
- Health checks call `radiusward probe http://127.0.0.1:9090/ready`.
- A gateway reloads its configuration on SIGHUP: `docker kill -s HUP <container>` (the entrypoint `exec`s Java, so
  the signal reaches it). What is reloaded: [ADR 0054](../adr/0054-config-reload.md).

## PostgreSQL export

The stack includes PostgreSQL 17 (172.28.0.40, `127.0.0.1:5432`, database `radius`, user `radiusward`, password
`PG_PASSWORD`, default `radiusward`). The members export to it (`export.sinks=pg` in
[config/cluster.properties](../../deploy/compose/config/cluster.properties)): one row per session in
`accounting_session`, like FreeRADIUS `radacct`, plus the `radacct` view.

```bash
docker compose -f deploy/compose/compose.yaml exec postgres psql -U radiusward radius -f /sql/examples.sql
docker compose -f deploy/compose/compose.yaml run --rm --entrypoint sh tools -c \
    'radiusward admin sinks --members 172.28.0.10,172.28.0.11,172.28.0.12 --egress-host $(hostname -i)'
```

`demo-failover.sh` also verifies that every acknowledged session reached PostgreSQL. Event history:
`sink.pg.mode=sessions+events`; no export: `RADIUSWARD_EXPORT_SINKS=` (empty). Details:
[export.md](export.md).

## Backup

`docker compose -f deploy/compose/compose.yaml --profile backup up -d` adds a continuous backup outside the cluster
(volume `radiusward_backup`, status on 127.0.0.1:9193); restoring after a lost quorum: [backup.md](backup.md).

## Monitoring

`docker compose -f deploy/compose/compose.yaml --profile monitoring up -d` adds Prometheus
(127.0.0.1:9095, with the alert rules) and Grafana (127.0.0.1:3000, five dashboards tagged "radiusward") —
[monitoring.md](monitoring.md).

## Querying the state

```bash
docker compose -f deploy/compose/compose.yaml run --rm --entrypoint radiusward tools \
    probe http://172.28.0.10:9090/state
docker compose -f deploy/compose/compose.yaml run --rm --entrypoint sh tools -c \
    'radiusward admin state --members 172.28.0.10,172.28.0.11,172.28.0.12 --egress-host $(hostname -i)'
```

`admin` reads the state through the cluster log, so its answer includes everything committed before it.

## Fault-injection tests

`scripts/linux-tests.sh` builds the image and a test image (LazyFS, iptables) and runs `testing/linux-tests`
([ADR 0016](../adr/0016-fault-injection-tests.md)). It uses the compose subnet, so stop the compose stack first.
With Colima it sets `DOCKER_HOST` and `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE` itself.
