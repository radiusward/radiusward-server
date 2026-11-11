#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Fault-injection tests in Linux containers (testing/linux-tests): builds radiusward.jar, the release image
# radiusward:dev, the test image radiusward-test:dev (LazyFS, iptables) and radiusward-systemd:dev (systemd as PID 1
# with the units of deploy/systemd, SystemdFailoverIT), then runs the tests.
#
#   scripts/linux-tests.sh                       all tests (~15 min)
#   scripts/linux-tests.sh PowerLossIT           one test class (comma-separated list works too)
#   SKIP_BUILD=1 scripts/linux-tests.sh ...      reuse the images
#   LINUX_TESTS_ARGS="-Dradiusward.outage.minutes=3 -Dradiusward.purge.minutes=8" scripts/linux-tests.sh
#                                                shorter runs than the nightly defaults (30 and 60 minutes)
#
# Needs Docker with privileged containers and /dev/fuse: Linux, or Colima on macOS (docs/operations/docker.md).
# A running deploy/compose stack uses the same subnet; stop it first.
set -euo pipefail
cd "$(dirname "$0")/.."

# Colima: Testcontainers needs the socket path on the host and the one inside the VM
if [[ -z "${DOCKER_HOST:-}" && -S "$HOME/.colima/default/docker.sock" ]]; then
    export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
    export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
fi

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
    ./mvnw -q -B install -DskipTests
    docker build -q -f deploy/docker/Dockerfile -t radiusward:dev .
    docker build -q -f testing/linux-tests/docker/Dockerfile.test -t radiusward-test:dev .
    docker build -q -f testing/linux-tests/docker/Dockerfile.systemd -t radiusward-systemd:dev .
fi

args=(-B -Plinux,reports verify -pl testing/linux-tests)
# shellcheck disable=SC2206
args+=(${LINUX_TESTS_ARGS:-})
if [[ $# -gt 0 ]]; then
    args+=("-Dit.test=$1")
fi
./mvnw "${args[@]}"
