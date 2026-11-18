<!--
Copyright 2026 The radiusward Authors
SPDX-License-Identifier: Apache-2.0
-->
# radiusward on Amazon ECS — example Terraform / OpenTofu module

The layout of [docs/operations/aws-ecs.md](../../../docs/operations/aws-ecs.md), the same as the CloudFormation
example in [`../cloudformation`](../cloudformation/radiusward-ecs.yaml), on Graviton (arm64): three members on EC2 (one
per availability zone and instance), two RADIUS servers and the backup on Fargate, one Network Load Balancer per RADIUS server, the backup on EFS with a nightly copy to S3.

**An example, not a tested product:** the project checks it with `tofu fmt -check` and `tofu validate` in CI, but has
not applied it in AWS. Review instance sizes, subnets and security groups before use.

```hcl
module "radiusward" {
  source             = "github.com/radiusward/radiusward-server//deploy/aws/terraform?ref=v0.1.0"
  vpc_id             = "vpc-0123456789abcdef0"
  vpc_cidr           = "10.0.0.0/16"
  member_subnet_ids  = ["subnet-a", "subnet-b", "subnet-c"]   # private, three zones: member i in subnet i
  server_subnet_ids = ["subnet-a", "subnet-b", "subnet-c"]
  nas_cidrs          = ["10.20.0.0/16"]
  server_properties = <<-EOT
    nas.branches.address=10.20.0.0/16
    nas.branches.secret=$${env:NAS_SECRET}
    nas.branches.id=1001
  EOT
}
```

After `apply`, set the secret in `nas_secret_arn` to what your NAS devices use and restart the RADIUS server services;
configure the NAS devices with both `server_addresses` as primary and secondary RADIUS servers.

| Variable | Default | Meaning |
|---|---|---|
| `vpc_id`, `vpc_cidr` | — | the VPC and its CIDR (health checks, management port) |
| `member_subnet_ids` | — | exactly three private subnets in three zones; member *i* runs in subnet *i*, pinned to its zone |
| `server_subnet_ids` | — | subnets of the RADIUS servers and their load balancers |
| `internal` | `true` | internal load balancers (NAS devices over VPN / Direct Connect) |
| `nas_cidrs` | — | where NAS devices send from |
| `server_properties` | one NAS entry | the RADIUS servers' properties file (NAS entries, identity stores; [configuration.md](../../../docs/configuration.md)) |
| `server_users` | a comment | a users file, written to `/tmp/users` in each RADIUS server task (a secret; a store with `type=file` and that `path` uses it) |
| `image` | `ghcr.io/radiusward/radiusward-server:0.1.0-rc.1` | the image (the latest release) |
| `profile` | `small` | `small` or `standard`: `RADIUSWARD_PROFILE` and the task sizes ([aws-ecs.md](../../../docs/operations/aws-ecs.md#sizes-per-profile-on-graviton)) |
| `member_instance_type` | by profile | Graviton instance for the members: `small` c7g.large, `standard` m7g.large |
| `member_volume_gib` | `100` | each member's EBS volume |
| `namespace` | `radiusward.local` | Cloud Map namespace of `node-0`…`node-2` |
