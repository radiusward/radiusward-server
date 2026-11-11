#!/bin/sh
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# TEST ONLY: apt-get update for the Ubuntu-based test images (docs/testing/strategy.md#test-images). GitHub's runners
# sometimes cannot resolve Ubuntu's own servers for hours; when the update fails against them, the sources are
# switched to other mirrors of the same archive (amd64: mirrors.edge.kernel.org, arm64: mirrors.ocf.berkeley.edu)
# and the update is repeated. apt-get install afterwards uses whichever worked.
set -eu
update() { apt-get -o Acquire::Retries=5 --error-on=any update; }
update && exit 0
echo "apt-update.sh: Ubuntu's servers cannot be reached, switching to fallback mirrors" >&2
sed -i \
    -e 's|http://archive.ubuntu.com/ubuntu|http://mirrors.edge.kernel.org/ubuntu|g' \
    -e 's|http://security.ubuntu.com/ubuntu|http://mirrors.edge.kernel.org/ubuntu|g' \
    -e 's|http://ports.ubuntu.com/ubuntu-ports|http://mirrors.ocf.berkeley.edu/ubuntu-ports|g' \
    /etc/apt/sources.list.d/ubuntu.sources
update
