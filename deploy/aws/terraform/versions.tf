# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
