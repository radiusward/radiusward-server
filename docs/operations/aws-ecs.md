# Amazon ECS

radiusward runs on Amazon ECS with the same image as everywhere else. Failover needs no scripts: the members elect a
new leader by themselves, ECS replaces a stopped task, and a member that comes back with an empty disk copies itself
from the others. This guide describes the layout and why each setting matters; two example templates set it up:
[CloudFormation](../../deploy/aws/cloudformation/radiusward-ecs.yaml) and
[Terraform / OpenTofu](../../deploy/aws/terraform).

> **The templates are examples.** CI checks them with `cfn-lint` and `tofu validate`; the project has not deployed
> them in AWS. Review sizes, subnets, security groups and costs before using them.

## Layout

```text
 NAS ──UDP 1812/1813──▶ NLB gateway-0 ──▶ gateway-0 (Fargate) ─┐
     (primary/secondary) NLB gateway-1 ──▶ gateway-1 (Fargate) ─┤  Aeron UDP
                                                               ▼
               node-0.radiusward.local   node-1…   node-2…   (ECS services on EC2 Graviton, one member per
               zone a                    zone b    zone c     zone and instance, EBS volume, /dev/shm, sysctls)
                         ▲  ClusterBackup
                         └──── backup (Fargate) ── EFS ──▶ nightly copy to S3 (EventBridge Scheduler)
                         members mount the EFS backup read-only: cluster.restore.from
```

| Part | ECS | Why |
|---|---|---|
| Members | **three services**, `node-0`, `node-1`, `node-2`, each `desiredCount: 1` | the member id is fixed per service (`RADIUSWARD_CLUSTER_NODE_ID`) |
| Member deployments | `minimumHealthyPercent: 0`, `maximumPercent: 100` | ECS normally starts the new task before stopping the old one; two tasks with the same member id must never run |
| Member names | Cloud Map private DNS (`node-0.radiusward.local`), A records of the task IPs | members find each other by name and re-resolve after a task moves ([ADR 0062](../adr/0062-members-and-gateways-on-kubernetes.md)) |
| Member capacity | **EC2 launch type** on Graviton (arm64), an Auto Scaling group of three instances, one per zone | `/dev/shm` for Aeron (`sharedMemorySize`), host sysctls for UDP buffers, CPU not shared |
| Member placement | member *i* in subnet *i*, placement constraint `memberOf attribute:ecs.availability-zone == <zone i>` | one member per availability zone, so one per instance and spread over failure domains; the task size is what the profile needs, not the whole instance |
| Member data | an ECS-managed EBS volume per task (gp3, encrypted) | created with each task: a replaced task starts empty and **seeds itself** from the other two ([ADR 0063](../adr/0063-seeding-a-replaced-member.md)) |
| Gateways | two services on Fargate, one Network Load Balancer each | two addresses for the NAS devices' primary and secondary servers; UDP listeners 1812 and 1813 |
| Source address | target type `ip` with `preserve_client_ip.enabled = true` | NAS entries are found by the source address |
| Backup | one service on Fargate, data on EFS | survives every member; `cluster-backup` ([ADR 0065](../adr/0065-cluster-backup.md)) |
| Off-site copy | an S3 bucket (versioned) and a nightly ECS task (`aws s3 sync`) | a copy outside the region's EFS |

### EC2 or Fargate for members

| Need | EC2 launch type | Fargate |
|---|---|---|
| `/dev/shm` for Aeron | `linuxParameters.sharedMemorySize` (512 MiB for `small`) | fixed and small: the Aeron directory goes to disk |
| UDP socket buffers (`net.core.rmem_max`, `wmem_max`) | host sysctls in the user data | not settable: Aeron uses smaller buffers |
| Fast disk with fsync | EBS gp3 / io2 or instance NVMe | ECS-managed EBS (also recreated per task) |
| Failover times as measured | yes | higher latency, not measured |

Members work on Fargate (set `RADIUSWARD_CLUSTER_AERON_DIR` to a directory on disk), but the templates use EC2.
Gateways and the backup are fine on Fargate; their Aeron directory is on disk (`/tmp`).

### Sizes per profile, on Graviton

The `Profile` parameter (`profile` variable) sets `RADIUSWARD_PROFILE` and sizes every task from the profile's heap,
direct memory and `/dev/shm` plus about 15 % ([ADR 0004](../adr/0004-memory-budget.md)):

| Profile | Member task | Member `/dev/shm` | Member instance (default) | Gateway task (Fargate) | Backup task (Fargate) |
|---|---|---|---|---|---|
| `small` | 1 vCPU, 1.5 GiB | 512 MiB | **c7g.large** (2 vCPU, 4 GiB) | 1 vCPU, 2 GiB | 0.5 vCPU, 1 GiB |
| `standard` | 2 vCPU, 4 GiB | 1 GiB | **m7g.large** (2 vCPU, 8 GiB) | 2 vCPU, 4 GiB | 0.5 vCPU, 1 GiB |

A member instance keeps a vCPU beside a `small` member for the operating system, the ECS agent and Aeron's threads;
`MemberInstanceType` overrides the default. Everything runs on **Graviton (arm64)**: the image is published for arm64
and amd64, Graviton gives more Java throughput per dollar, and the throughput of both profiles is to be measured in
an AWS run (until then the sizes are the ones measured in containers and on Kubernetes). For x86, set the
instance type, the x86 ECS AMI parameter and `CpuArchitecture: X86_64`.

### One member per availability zone

The three member subnets are in three zones, the Auto Scaling group keeps one instance in each, and member *i* may
only run in zone *i*. Two members never share an instance or a zone, and losing a zone leaves the quorum. When an
instance is replaced, its member waits for the new instance in its zone (ECS keeps the task pending meanwhile), then
starts with a new EBS volume and seeds itself from the other two. In CloudFormation pass `MemberSubnetIds` and their
zones `MemberAvailabilityZones` in the same order (a rule checks the zones belong to the subnets); Terraform reads the
zones from the subnets.

## Configuration on ECS

Every key can be set as an environment variable (`cluster.members` → `RADIUSWARD_CLUSTER_MEMBERS`,
[ADR 0010](../adr/0010-configuration.md)); each process still wants one `--config` file, so the containers start
with a small `sh -c` that writes it and then runs the image's entrypoint:

- **Members:** an empty properties file; everything from the environment: `RADIUSWARD_CLUSTER_NODE_ID`,
  `RADIUSWARD_CLUSTER_MEMBERS` (the three Cloud Map names), `RADIUSWARD_CLUSTER_SEED_TIMEOUT=20s`,
  `RADIUSWARD_CLUSTER_RESTORE_FROM=/mnt/backup/backup` (the EFS backup, mounted read-only).
- **Gateways:** NAS entries (`nas.<name>.*`) and identity stores are named keys that only a file defines, so the
  gateways' properties live in an SSM parameter, passed as a secret (`GATEWAY_PROPERTIES`) and written to
  `/tmp/gateway.properties` at start. The NAS shared secret is a Secrets Manager secret (`NAS_SECRET`), referenced
  as `${env:NAS_SECRET}` in the properties. Change the parameter, then restart the gateway services.
- **Task addresses:** members reply to a gateway, and send backups, to an address the task only knows at runtime
  (awsvpc networking). The start command sets `RADIUSWARD_GATEWAY_EGRESS_HOST` and `RADIUSWARD_BACKUP_HOST` from
  `hostname -i`, which is the task's ENI address on ECS.
- **Users file or SQL store:** add the store to the gateway properties; a users file can be another SSM parameter
  written to `/tmp/users` the same way, or use the SQL store (`auth.store.<name>.type=sql`) against RDS.

## Failover and recovery

| What fails | What happens | Your part |
|---|---|---|
| A member's task or instance | the others elect a leader (about 2 s); ECS starts the task again (on another instance when needed) with a new EBS volume, and it seeds itself from the other two | nothing |
| A gateway's task | the NAS devices use the other gateway (primary/secondary); ECS restarts the task | configure both gateways on every NAS |
| An availability zone | two of three members keep the quorum (one member per zone); the backup and EFS are multi-zone | nothing |
| Two or three members at once | no quorum; replaced members find nobody to seed from and **restore themselves from the backup** on EFS (`cluster.restore.from`) — every member from the same backup — then elect a leader and go on from its position | nothing; check the backup's lag first ([backup.md](backup.md)) |
| The backup's task | the cluster runs on; the next task fetches the latest snapshot | nothing |
| EFS or the region | restore from the S3 copy into EFS, then start the members | copy the S3 prefix back to the backup directory |

What a restore after a total loss gives back is the backup's position: the metrics `radiusward_backup_*` and the
alerts `RadiuswardBackupBehind`, `RadiuswardBackupSnapshotOld` watch it ([monitoring.md](monitoring.md)).

### The S3 copy

The nightly task copies the EFS backup to a versioned bucket with `aws s3 sync`. The backup keeps writing while it is
copied, so a copy taken under load may end in the middle of a write; the versioned bucket keeps the earlier ones. For
a quiet copy, scale the backup service to 0, run the sync task, and scale it back to 1 (the cluster is unaffected).
To restore from S3, copy the prefix back into the backup directory on EFS (`aws s3 sync s3://<bucket>/backup/
<efs>/radiusward-backup/backup/`) before the members start.

## Upgrades

Update the three member services **one at a time**, and start the next only when the previous member reports ready
(`/ready` on port 9090, or the service's running task healthy). Each update stops the member's task first
(`minimumHealthyPercent: 0`); its new task gets a new EBS volume and seeds itself from the other two. Gateways can be
updated one at a time the same way; NAS devices retry the other one meanwhile. State-machine versions activate on
their own once every member runs the new image ([ADR 0005](../adr/0005-log-determinism-versioning.md)).

## Monitoring

Every task serves `/metrics` on port 9090 (reachable from the VPC). Scrape it with Prometheus (ECS service discovery,
or the Cloud Map names for members) and import the dashboards and alerts of
[deploy/monitoring](../../deploy/monitoring) ([monitoring.md](monitoring.md)); Container Insights, enabled by the
templates, shows CPU and memory per task. Logs go to CloudWatch Logs (`/radiusward/<name>`).

## Costs and limits

- Three Graviton instances (c7g.large for `small`, m7g.large for `standard`), two Fargate gateways, one Fargate
  backup (all arm64), two Network Load Balancers, EFS and S3 storage, CloudWatch logs.
- Three member subnets in three availability zones: EFS needs one mount target per zone, and members should not share
  a zone.
- awsvpc networking on EC2 uses one ENI per member task; every listed instance type has enough.

## Throughput test

To find the ceiling of a profile, load generators run **outside the cluster** on c7g.xlarge (arm64) instances in the
VPC, sending through both load balancers as NAS devices do, with the image's `radclient`:

```bash
docker run --rm --network host ghcr.io/radiusward/radiusward-server:<version> radclient load \
  --server <gateway-0 NLB>:1813,<gateway-1 NLB>:1813 --retry-other-server --secret <NAS secret> \
  --nas 50 --sessions 250000 --rate 5000 --duration 600s --interim 300s --access-rate 500
```

Their addresses need a NAS entry in the gateway properties. Raise `--rate` step by step until p99 latency or failed
requests show the limit; the numbers belong in this guide once measured.
- Network Load Balancers forward UDP without TLS; RadSec (TCP 2083) needs a TCP listener added to the templates.
