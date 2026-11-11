# Backup and restore

Three members survive the loss of one; a member whose volume was replaced copies itself from the other two
([ADR 0063](../adr/0063-seeding-a-replaced-member.md)). For everything worse — two members lost at once, or the whole
cluster — radiusward keeps a **continuous backup outside the cluster** ([ADR 0065](../adr/0065-cluster-backup.md)):
the latest snapshot and the live log, recorded from a follower, in a member's layout.

| | Kubernetes (Helm) | Docker compose | systemd |
|---|---|---|---|
| Backup | `backup` StatefulSet, on by default (`backup.*` values) | `docker compose --profile backup up -d` | `radiusward-backup.service`, `/etc/radiusward/backup.properties` |
| Data | its PVC `data-<release>-radiusward-backup-0` | volume `radiusward_backup` | `/var/lib/radiusward/backup` |
| Status | `/ready`, `/metrics` of the backup pod | `127.0.0.1:9193` | management port |
| Restore | `scripts/k8s-restore.sh -n <ns> -r <release>` | the commands below | the commands below |

Settings (`backup.host`, `backup.port`, `backup.source`, `backup.interval`, `backup.data.dir`): see
[configuration.md](../configuration.md#cluster-backup). Run the backup on another machine or volume than the members.

## Is the backup good?

- `/ready` is up while it records the live log and holds a snapshot: a restore would work now.
- `radiusward_backup_live_log_position_bytes` close to the members' `radiusward_cluster_log_position_bytes`: what a
  restore would lose is the difference. Alerts: `RadiuswardBackupNotBackingUp`, `RadiuswardBackupBehind`,
  `RadiuswardBackupSnapshotOld` ([monitoring.md](monitoring.md)).
- After the cluster's first snapshot the backup picks it up within `backup.interval` (30 min by default; restart the
  backup to fetch it at once).

Copies elsewhere (object storage, another site) are file copies of the backup's data directory while the backup is
stopped, e.g. a nightly `systemctl stop radiusward-backup && tar … && systemctl start radiusward-backup`.

## Restore after a lost quorum

All three members are restored from the same backup and started together; they elect a leader and go on from the
backup's position. `cluster-restore` refuses to write over a member's data, and checks that the backup holds a
snapshot.

**Kubernetes:**

```bash
scripts/k8s-restore.sh -n radius -r radiusward     # stops members and backup, restores all three, starts them again
```

It copies the backup out through a temporary pod, gives every member an empty volume, restores it in a temporary pod
and scales the StatefulSets back up; each pod mounts one volume, so node-local volumes work. The nightly Kubernetes
tests run it (`restore-quorum`).

**Docker compose** (the backup volume mounted read-only):

```bash
c="docker compose -f deploy/compose/compose.yaml --profile backup"
$c stop node-0 node-1 node-2 backup && $c rm -f node-0 node-1 node-2
docker volume rm radiusward_node-0 radiusward_node-1 radiusward_node-2      # what is left of the members
for i in 0 1 2; do
  $c run --rm --no-deps -v radiusward_backup:/backup:ro node-$i \
     cluster-restore --from /backup/backup --config /etc/radiusward/cluster.properties
done
$c up -d --wait
```

**systemd**, on every member host (copy the backup's directory there first, e.g. with `rsync`):

```bash
sudo systemctl stop radiusward-node
sudo mv /var/lib/radiusward/node-<id> /var/lib/radiusward/node-<id>.lost        # keep what is left
sudo -u radiusward RADIUSWARD_CLUSTER_NODE_ID=<id> radiusward cluster-restore \
     --from /var/tmp/radiusward-backup --config /etc/radiusward/cluster.properties
sudo systemctl start radiusward-node                                               # on all three
```

## A single lost member

Nothing to do with the backup: delete the member's volume (or start it with an empty data directory) and it seeds
itself from the other two (`cluster.seed.timeout`, [kubernetes.md](kubernetes.md#replacing-a-members-volume)).
