# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# radiusward on Amazon ECS on Graviton (arm64) — an EXAMPLE module (docs/operations/aws-ecs.md), the same layout as
# deploy/aws/cloudformation/radiusward-ecs.yaml. The project validates it with `tofu validate` only; it has not been
# applied in AWS by the project. Review sizes, subnets and security groups before use.

data "aws_region" "current" {}

data "aws_ssm_parameter" "ecs_ami" {
  name = "/aws/service/ecs/optimized-ami/amazon-linux-2023/arm64/recommended/image_id"
}

# the zone of each member subnet: member i is pinned to the zone of subnet i (one member per zone and per instance)
data "aws_subnet" "member" {
  for_each = { for i, id in var.member_subnet_ids : tostring(i) => id }
  id       = each.value
}

locals {
  # task sizes per profile: heap + direct memory + /dev/shm of deploy/docker/entrypoint.sh plus about 15 % (ADR 0004)
  sizes = {
    small    = { member_cpu = 1024, member_memory = 1536, member_shm = 512, member_instance = "c7g.large", gateway_cpu = 1024, gateway_memory = 2048 }
    standard = { member_cpu = 2048, member_memory = 4096, member_shm = 1024, member_instance = "m7g.large", gateway_cpu = 2048, gateway_memory = 4096 }
  }
  size         = local.sizes[var.profile]
  member_zones = { for i, s in data.aws_subnet.member : i => s.availability_zone }
  arm64        = { cpu_architecture = "ARM64", operating_system_family = "LINUX" }
}

locals {
  members      = ["0", "1", "2"]
  gateways     = ["0", "1"]
  member_names = join(",", [for id in local.members : "node-${id}.${var.namespace}"])
  log_options = {
    "awslogs-group"  = aws_cloudwatch_log_group.radiusward.name
    "awslogs-region" = data.aws_region.current.region
  }
  health = {
    command     = ["CMD", "radiusward", "probe", "http://127.0.0.1:9090/health"]
    interval    = 15
    timeout     = 5
    retries     = 4
    startPeriod = 120
  }
}

# ---------------------------------------------------------------- logs, secrets, gateway configuration

resource "aws_cloudwatch_log_group" "radiusward" {
  name              = "/radiusward/${var.name}"
  retention_in_days = 30
}

resource "aws_secretsmanager_secret" "nas" {
  name_prefix = "${var.name}-nas-"
  description = "the RADIUS shared secret of the NAS devices (NAS_SECRET in the gateway properties)"
}

# a users file for the gateways, written to /tmp/users in each gateway task (identity store type file)
resource "aws_secretsmanager_secret" "users" {
  name_prefix = "${var.name}-users-"
  description = "the gateways' users file (/tmp/users; identity store type file)"
}

resource "aws_secretsmanager_secret_version" "users" {
  secret_id     = aws_secretsmanager_secret.users.id
  secret_string = var.gateway_users
}

resource "aws_ssm_parameter" "gateway_properties" {
  name  = "/${var.name}/gateway.properties"
  type  = "String"
  value = var.gateway_properties
}

# ---------------------------------------------------------------- security groups

resource "aws_security_group" "member" {
  name_prefix = "${var.name}-member-"
  description = "radiusward members"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "gateway" {
  name_prefix = "${var.name}-gateway-"
  description = "radiusward gateways"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "backup" {
  name_prefix = "${var.name}-backup-"
  description = "radiusward cluster backup"
  vpc_id      = var.vpc_id
}

resource "aws_security_group" "efs" {
  name_prefix = "${var.name}-efs-"
  description = "radiusward backup file system"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_egress_rule" "all" {
  for_each          = { member = aws_security_group.member.id, gateway = aws_security_group.gateway.id, backup = aws_security_group.backup.id }
  security_group_id = each.value
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# Aeron between members, gateways and the backup: fixed ports (cluster.base.port + 100 x id + 0..5, backup.port
# + 0..3) and ephemeral ones (replies, replication), so all UDP among the three groups
locals {
  aeron_rules = {
    member_from_member  = [aws_security_group.member.id, aws_security_group.member.id]
    member_from_gateway = [aws_security_group.member.id, aws_security_group.gateway.id]
    member_from_backup  = [aws_security_group.member.id, aws_security_group.backup.id]
    gateway_from_member = [aws_security_group.gateway.id, aws_security_group.member.id]
    backup_from_member  = [aws_security_group.backup.id, aws_security_group.member.id]
  }
}

resource "aws_vpc_security_group_ingress_rule" "aeron" {
  for_each                     = local.aeron_rules
  security_group_id            = each.value[0]
  referenced_security_group_id = each.value[1]
  ip_protocol                  = "udp"
  from_port                    = 0
  to_port                      = 65535
}

resource "aws_vpc_security_group_ingress_rule" "management" {
  for_each          = { member = aws_security_group.member.id, gateway = aws_security_group.gateway.id, backup = aws_security_group.backup.id }
  security_group_id = each.value
  description       = "management, metrics and load balancer health checks"
  ip_protocol       = "tcp"
  from_port         = 9090
  to_port           = 9090
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_ingress_rule" "radius" {
  for_each          = toset(var.nas_cidrs)
  security_group_id = aws_security_group.gateway.id
  description       = "RADIUS from NAS devices"
  ip_protocol       = "udp"
  from_port         = 1812
  to_port           = 1813
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "nfs" {
  for_each                     = { member = aws_security_group.member.id, backup = aws_security_group.backup.id }
  security_group_id            = aws_security_group.efs.id
  referenced_security_group_id = each.value
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
}

# ---------------------------------------------------------------- IAM

data "aws_iam_policy_document" "ecs_tasks" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_configuration" {
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = [aws_secretsmanager_secret.nas.arn, aws_secretsmanager_secret.users.arn] },
      { Effect = "Allow", Action = "ssm:GetParameters", Resource = aws_ssm_parameter.gateway_properties.arn },
    ]
  })
}

# ECS creates and attaches the members' EBS volumes with this role
resource "aws_iam_role" "volumes" {
  name_prefix = "${var.name}-volumes-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ecs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "volumes" {
  role       = aws_iam_role.volumes.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSInfrastructureRolePolicyForVolumes"
}

resource "aws_iam_role" "instance" {
  name_prefix = "${var.name}-instance-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "instance" {
  for_each = toset([
    "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ])
  role       = aws_iam_role.instance.name
  policy_arn = each.value
}

resource "aws_iam_instance_profile" "instance" {
  name_prefix = "${var.name}-"
  role        = aws_iam_role.instance.name
}

resource "aws_iam_role" "sync" {
  name_prefix        = "${var.name}-sync-"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks.json
}

resource "aws_iam_role_policy" "sync" {
  role = aws_iam_role.sync.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "s3:ListBucket", Resource = aws_s3_bucket.backup.arn },
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"], Resource = "${aws_s3_bucket.backup.arn}/*" },
    ]
  })
}

resource "aws_iam_role" "scheduler" {
  name_prefix = "${var.name}-scheduler-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "scheduler.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "ecs:RunTask", Resource = aws_ecs_task_definition.sync.arn },
      { Effect = "Allow", Action = "iam:PassRole", Resource = [aws_iam_role.execution.arn, aws_iam_role.sync.arn] },
    ]
  })
}

# ---------------------------------------------------------------- ECS cluster and member capacity

resource "aws_ecs_cluster" "radiusward" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_launch_template" "member" {
  name_prefix   = "${var.name}-member-"
  image_id      = data.aws_ssm_parameter.ecs_ami.value
  instance_type = coalesce(var.member_instance_type, local.size.member_instance)
  iam_instance_profile {
    arn = aws_iam_instance_profile.instance.arn
  }
  metadata_options {
    http_tokens = "required"
  }
  user_data = base64encode(<<-EOT
    #!/bin/bash
    echo "ECS_CLUSTER=${aws_ecs_cluster.radiusward.name}" >> /etc/ecs/ecs.config
    # room for Aeron's UDP socket buffers (docs/operations/bare-metal.md)
    printf 'net.core.rmem_max = 4194304\nnet.core.wmem_max = 4194304\n' > /etc/sysctl.d/99-radiusward.conf
    sysctl --system
  EOT
  )
}

# one instance per availability zone: the group balances across the three subnets, and member i is pinned to zone i
resource "aws_autoscaling_group" "member" {
  name_prefix         = "${var.name}-member-"
  min_size            = 3
  max_size            = 3
  desired_capacity    = 3
  vpc_zone_identifier = var.member_subnet_ids
  launch_template {
    id      = aws_launch_template.member.id
    version = aws_launch_template.member.latest_version
  }
  tag {
    key                 = "AmazonECSManaged"
    value               = "true"
    propagate_at_launch = true
  }
}

resource "aws_ecs_capacity_provider" "member" {
  name = "${var.name}-member"
  auto_scaling_group_provider {
    auto_scaling_group_arn         = aws_autoscaling_group.member.arn
    managed_termination_protection = "DISABLED"
    managed_scaling {
      status = "DISABLED"
    }
  }
}

resource "aws_ecs_cluster_capacity_providers" "radiusward" {
  cluster_name       = aws_ecs_cluster.radiusward.name
  capacity_providers = ["FARGATE", aws_ecs_capacity_provider.member.name]
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ---------------------------------------------------------------- service discovery: node-0, node-1, node-2

resource "aws_service_discovery_private_dns_namespace" "radiusward" {
  name = var.namespace
  vpc  = var.vpc_id
}

resource "aws_service_discovery_service" "node" {
  for_each = toset(local.members)
  name     = "node-${each.key}"
  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.radiusward.id
    routing_policy = "MULTIVALUE"
    dns_records {
      type = "A"
      ttl  = 5
    }
  }
  health_check_custom_config {}
}

# ---------------------------------------------------------------- backup file system

resource "aws_efs_file_system" "backup" {
  encrypted = true
  tags      = { Name = "${var.name}-backup" }
}

resource "aws_efs_mount_target" "backup" {
  for_each        = toset(var.member_subnet_ids)
  file_system_id  = aws_efs_file_system.backup.id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "backup" {
  file_system_id = aws_efs_file_system.backup.id
  posix_user {
    uid = 10001
    gid = 10001
  }
  root_directory {
    path = "/radiusward-backup"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "750"
    }
  }
}

# ---------------------------------------------------------------- members
# One task definition and one service per member: the member id is fixed per service, and minimum 0 / maximum
# 100 % makes ECS stop a member's task before it starts the next — never two tasks with the same id.

resource "aws_ecs_task_definition" "node" {
  for_each                 = toset(local.members)
  family                   = "${var.name}-node-${each.key}"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  cpu                      = tostring(local.size.member_cpu)
  memory                   = tostring(local.size.member_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    cpu_architecture        = local.arm64.cpu_architecture
    operating_system_family = local.arm64.operating_system_family
  }
  volume {
    name                = "data"
    configure_at_launch = true
  }
  volume {
    name = "backup"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.backup.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.backup.id
        iam             = "DISABLED"
      }
    }
  }
  container_definitions = jsonencode([{
    name        = "node"
    image       = var.image
    essential   = true
    stopTimeout = 60
    entryPoint  = ["/bin/sh", "-c"]
    # every key from the environment (ADR 0010); the process wants one --config file
    command = [": > /tmp/radiusward.properties && exec /usr/local/bin/radiusward cluster-node --config /tmp/radiusward.properties"]
    environment = [
      { name = "RADIUSWARD_PROFILE", value = var.profile },
      { name = "RADIUSWARD_CLUSTER_NODE_ID", value = each.key },
      { name = "RADIUSWARD_CLUSTER_MEMBERS", value = local.member_names },
      { name = "RADIUSWARD_CLUSTER_SEED_TIMEOUT", value = "20s" },
      { name = "RADIUSWARD_CLUSTER_RESTORE_FROM", value = "/mnt/backup/backup" },
      { name = "RADIUSWARD_MANAGEMENT_HTTP_HOST", value = "0.0.0.0" },
    ]
    portMappings    = [{ containerPort = 9090, protocol = "tcp" }]
    linuxParameters = { sharedMemorySize = local.size.member_shm, initProcessEnabled = true }
    mountPoints = [
      { sourceVolume = "data", containerPath = "/var/lib/radiusward" },
      { sourceVolume = "backup", containerPath = "/mnt/backup", readOnly = true },
    ]
    healthCheck      = local.health
    logConfiguration = { logDriver = "awslogs", options = merge(local.log_options, { "awslogs-stream-prefix" = "node-${each.key}" }) }
  }])
}

resource "aws_ecs_service" "node" {
  for_each                           = toset(local.members)
  name                               = "node-${each.key}"
  cluster                            = aws_ecs_cluster.radiusward.id
  task_definition                    = aws_ecs_task_definition.node[each.key].arn
  desired_count                      = 1
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  enable_execute_command             = true
  capacity_provider_strategy {
    capacity_provider = aws_ecs_capacity_provider.member.name
    weight            = 1
  }
  # member i in zone i: one member per zone and per instance, spread over failure domains
  placement_constraints {
    type       = "memberOf"
    expression = "attribute:ecs.availability-zone == ${local.member_zones[each.key]}"
  }
  network_configuration {
    subnets         = [var.member_subnet_ids[tonumber(each.key)]]
    security_groups = [aws_security_group.member.id]
  }
  service_registries {
    registry_arn = aws_service_discovery_service.node[each.key].arn
  }
  # recreated with each task: a replaced task seeds itself from the others (ADR 0063)
  volume_configuration {
    name = "data"
    managed_ebs_volume {
      role_arn         = aws_iam_role.volumes.arn
      size_in_gb       = var.member_volume_gib
      volume_type      = "gp3"
      file_system_type = "ext4"
      encrypted        = true
    }
  }
  depends_on = [aws_ecs_cluster_capacity_providers.radiusward, aws_efs_mount_target.backup]
}

# ---------------------------------------------------------------- gateways, one load balancer each

resource "aws_ecs_task_definition" "gateway" {
  for_each                 = toset(local.gateways)
  family                   = "${var.name}-gateway-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(local.size.gateway_cpu)
  memory                   = tostring(local.size.gateway_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    cpu_architecture        = local.arm64.cpu_architecture
    operating_system_family = local.arm64.operating_system_family
  }
  container_definitions = jsonencode([{
    name        = "gateway"
    image       = var.image
    essential   = true
    stopTimeout = 30
    entryPoint  = ["/bin/sh", "-c"]
    # the properties come from SSM, the users file from Secrets Manager; the members send replies to the task's
    # own address
    command = [join(" && ", [
      "printf '%s\\n' \"$GATEWAY_PROPERTIES\" > /tmp/gateway.properties",
      "printf '%s\\n' \"$GATEWAY_USERS\" > /tmp/users",
      "ip=$(hostname -i)",
      "export RADIUSWARD_GATEWAY_EGRESS_HOST=$${ip%% *}",
      "exec /usr/local/bin/radiusward gateway --config /tmp/gateway.properties",
    ])]
    environment = [
      { name = "RADIUSWARD_PROFILE", value = var.profile },
      { name = "RADIUSWARD_GATEWAY_ID", value = each.key },
      { name = "RADIUSWARD_CLUSTER_MEMBERS", value = local.member_names },
      { name = "RADIUSWARD_GATEWAY_SHUTDOWN_DRAIN", value = "5s" },
      { name = "RADIUSWARD_GATEWAY_AERON_DIR", value = "/tmp/aeron-gateway" },
      { name = "RADIUSWARD_MANAGEMENT_HTTP_HOST", value = "0.0.0.0" },
    ]
    secrets = [
      { name = "NAS_SECRET", valueFrom = aws_secretsmanager_secret.nas.arn },
      { name = "GATEWAY_PROPERTIES", valueFrom = aws_ssm_parameter.gateway_properties.arn },
      { name = "GATEWAY_USERS", valueFrom = aws_secretsmanager_secret_version.users.secret_arn },
    ]
    portMappings = [
      { containerPort = 1812, protocol = "udp" },
      { containerPort = 1813, protocol = "udp" },
      { containerPort = 9090, protocol = "tcp" },
    ]
    healthCheck      = merge(local.health, { startPeriod = 60 })
    logConfiguration = { logDriver = "awslogs", options = merge(local.log_options, { "awslogs-stream-prefix" = "gateway-${each.key}" }) }
  }])
}

resource "aws_lb" "gateway" {
  for_each                         = toset(local.gateways)
  name                             = "${var.name}-gw-${each.key}"
  load_balancer_type               = "network"
  internal                         = var.internal
  subnets                          = var.gateway_subnet_ids
  enable_cross_zone_load_balancing = true
}

locals {
  # gateway id x RADIUS port
  gateway_ports = { for pair in setproduct(local.gateways, ["1812", "1813"]) : "${pair[0]}-${pair[1]}" => { id = pair[0], port = tonumber(pair[1]) } }
}

resource "aws_lb_target_group" "gateway" {
  for_each             = local.gateway_ports
  name                 = "${var.name}-gw-${each.key}"
  vpc_id               = var.vpc_id
  protocol             = "UDP"
  port                 = each.value.port
  target_type          = "ip"
  deregistration_delay = 10
  # NAS entries are found by the source address: it must reach the gateway unchanged
  preserve_client_ip = "true"
  health_check {
    protocol = "HTTP"
    port     = "9090"
    path     = "/ready"
  }
}

resource "aws_lb_listener" "gateway" {
  for_each          = local.gateway_ports
  load_balancer_arn = aws_lb.gateway[each.value.id].arn
  protocol          = "UDP"
  port              = each.value.port
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway[each.key].arn
  }
}

resource "aws_ecs_service" "gateway" {
  for_each                           = toset(local.gateways)
  name                               = "gateway-${each.key}"
  cluster                            = aws_ecs_cluster.radiusward.id
  task_definition                    = aws_ecs_task_definition.gateway[each.key].arn
  desired_count                      = 1
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  health_check_grace_period_seconds  = 60
  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
  network_configuration {
    subnets         = var.gateway_subnet_ids
    security_groups = [aws_security_group.gateway.id]
  }
  dynamic "load_balancer" {
    for_each = ["1812", "1813"]
    content {
      container_name   = "gateway"
      container_port   = tonumber(load_balancer.value)
      target_group_arn = aws_lb_target_group.gateway["${each.key}-${load_balancer.value}"].arn
    }
  }
  depends_on = [aws_ecs_cluster_capacity_providers.radiusward, aws_lb_listener.gateway]
}

# ---------------------------------------------------------------- the continuous backup (ADR 0065)

resource "aws_ecs_task_definition" "backup" {
  family                   = "${var.name}-backup"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    cpu_architecture        = local.arm64.cpu_architecture
    operating_system_family = local.arm64.operating_system_family
  }
  volume {
    name = "backup"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.backup.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.backup.id
        iam             = "DISABLED"
      }
    }
  }
  container_definitions = jsonencode([{
    name        = "backup"
    image       = var.image
    essential   = true
    stopTimeout = 30
    entryPoint  = ["/bin/sh", "-c"]
    # the members answer the backup at the task's own address
    command = [join(" && ", [
      ": > /tmp/backup.properties",
      "ip=$(hostname -i)",
      "export RADIUSWARD_BACKUP_HOST=$${ip%% *}",
      "exec /usr/local/bin/radiusward cluster-backup --config /tmp/backup.properties",
    ])]
    environment = [
      { name = "RADIUSWARD_PROFILE", value = var.profile },
      { name = "RADIUSWARD_CLUSTER_MEMBERS", value = local.member_names },
      { name = "RADIUSWARD_BACKUP_DATA_DIR", value = "/var/lib/radiusward/backup" },
      { name = "RADIUSWARD_BACKUP_AERON_DIR", value = "/tmp/aeron-backup" },
      { name = "RADIUSWARD_BACKUP_SOURCE", value = "follower" },
      { name = "RADIUSWARD_BACKUP_INTERVAL", value = "30m" },
      { name = "RADIUSWARD_MANAGEMENT_HTTP_HOST", value = "0.0.0.0" },
    ]
    portMappings     = [{ containerPort = 9090, protocol = "tcp" }]
    mountPoints      = [{ sourceVolume = "backup", containerPath = "/var/lib/radiusward" }]
    healthCheck      = merge(local.health, { interval = 30, startPeriod = 60 })
    logConfiguration = { logDriver = "awslogs", options = merge(local.log_options, { "awslogs-stream-prefix" = "backup" }) }
  }])
}

resource "aws_ecs_service" "backup" {
  name                               = "backup"
  cluster                            = aws_ecs_cluster.radiusward.id
  task_definition                    = aws_ecs_task_definition.backup.arn
  desired_count                      = 1
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
  network_configuration {
    subnets         = var.member_subnet_ids
    security_groups = [aws_security_group.backup.id]
  }
  depends_on = [aws_ecs_cluster_capacity_providers.radiusward, aws_efs_mount_target.backup]
}

# ---------------------------------------------------------------- nightly copy of the backup to S3

resource "aws_s3_bucket" "backup" {
  bucket_prefix = "${var.name}-backup-"
}

resource "aws_s3_bucket_versioning" "backup" {
  bucket = aws_s3_bucket.backup.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backup" {
  bucket                  = aws_s3_bucket.backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    id     = "old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# The backup keeps writing while it is copied: a copy taken under load may end mid-write; the bucket keeps
# versions, and docs/operations/aws-ecs.md says how to take a quiet copy.
resource "aws_ecs_task_definition" "sync" {
  family                   = "${var.name}-backup-to-s3"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.execution.arn
  # the AWS CLI image is amd64 + arm64
  runtime_platform {
    cpu_architecture        = local.arm64.cpu_architecture
    operating_system_family = local.arm64.operating_system_family
  }
  task_role_arn = aws_iam_role.sync.arn
  volume {
    name = "backup"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.backup.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.backup.id
        iam             = "DISABLED"
      }
    }
  }
  container_definitions = jsonencode([{
    name             = "sync"
    image            = "public.ecr.aws/aws-cli/aws-cli:latest"
    essential        = true
    command          = ["s3", "sync", "/backup/backup", "s3://${aws_s3_bucket.backup.bucket}/backup/", "--delete"]
    mountPoints      = [{ sourceVolume = "backup", containerPath = "/backup", readOnly = true }]
    logConfiguration = { logDriver = "awslogs", options = merge(local.log_options, { "awslogs-stream-prefix" = "backup-to-s3" }) }
  }])
}

resource "aws_scheduler_schedule" "sync" {
  name                = "${var.name}-backup-to-s3"
  description         = "copy the cluster backup to S3 every night"
  schedule_expression = "cron(0 3 * * ? *)"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = aws_ecs_cluster.radiusward.arn
    role_arn = aws_iam_role.scheduler.arn
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.sync.arn
      launch_type         = "FARGATE"
      network_configuration {
        subnets          = var.member_subnet_ids
        security_groups  = [aws_security_group.backup.id]
        assign_public_ip = false
      }
    }
  }
}
