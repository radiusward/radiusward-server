# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0

output "gateway_addresses" {
  description = "primary and secondary RADIUS servers for the NAS devices (UDP 1812/1813)"
  value       = [for id in local.gateways : aws_lb.gateway[id].dns_name]
}

output "nas_secret_arn" {
  description = "set this secret to the shared secret your NAS devices use, then restart the gateway services"
  value       = aws_secretsmanager_secret.nas.arn
}

output "backup_bucket" {
  value = aws_s3_bucket.backup.bucket
}

output "backup_file_system_id" {
  value = aws_efs_file_system.backup.id
}
