# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0

variable "name" {
  description = "prefix of every resource name"
  type        = string
  default     = "radiusward"
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  description = "the VPC's CIDR (load balancer health checks and the management port)"
  type        = string
}

variable "member_subnet_ids" {
  description = "private subnets, one per availability zone (three), for members, backup and EFS"
  type        = list(string)
  validation {
    condition     = length(var.member_subnet_ids) == 3
    error_message = "three subnets, one per availability zone: one EFS mount target and one member in each"
  }
}

variable "gateway_subnet_ids" {
  description = "subnets for the gateways and their load balancers (public ones when internal = false)"
  type        = list(string)
}

variable "internal" {
  description = "internal load balancers (NAS devices reach them over VPN or Direct Connect)"
  type        = bool
  default     = true
}

variable "nas_cidrs" {
  description = "where NAS devices send from (RADIUS UDP 1812/1813 to the gateways)"
  type        = list(string)
}

variable "gateway_properties" {
  description = "the gateways' properties: NAS entries, identity stores (docs/configuration.md); the NAS secret is NAS_SECRET"
  type        = string
  default     = <<-EOT
    nas.site.address=10.0.0.0/8
    nas.site.secret=$${env:NAS_SECRET}
    nas.site.id=1001
  EOT
}

variable "image" {
  type    = string
  default = "ghcr.io/radiusward/radiusward-server:0.1.0"
}

variable "profile" {
  type    = string
  default = "small"
  validation {
    condition     = contains(["small", "standard", "large"], var.profile)
    error_message = "small, standard or large"
  }
}

variable "member_instance_type" {
  description = "one member per instance (its task takes all 2 vCPU of the default type)"
  type        = string
  default     = "m6i.large"
}

variable "member_volume_gib" {
  type    = number
  default = 100
}

variable "namespace" {
  description = "private DNS namespace; members are node-0, node-1 and node-2 in it"
  type        = string
  default     = "radiusward.local"
}
