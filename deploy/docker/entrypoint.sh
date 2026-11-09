#!/bin/sh
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Container entrypoint: picks JVM flags for the component and RADIUSWARD_PROFILE (ADR 0004), sets
# container-friendly defaults, then runs radiusward. JAVA_OPTS is appended last and wins.
set -eu

component="${1:-version}"
profile="${RADIUSWARD_PROFILE:-small}"

case "$component:$profile" in
    cluster-node:small)    heap=384m ;;
    cluster-node:standard) heap=1g ;;
    cluster-node:large)    heap=2560m ;;
    gateway:small)         heap=192m ;;
    gateway:standard)      heap=384m ;;
    gateway:large)         heap=768m ;;
    radclient:*)           heap=512m ;;
    admin:*)               heap=256m ;;   # verifiers keep the last event of every session of an ack log
    *)                     heap=64m ;;    # probe, version, cluster-tool
esac

# defaults for config keys (environment overrides beat properties files; see docs/configuration.md)
export RADIUSWARD_CLUSTER_DATA_DIR="${RADIUSWARD_CLUSTER_DATA_DIR:-/var/lib/radiusward}"
export RADIUSWARD_CLUSTER_AERON_DIR="${RADIUSWARD_CLUSTER_AERON_DIR:-/dev/shm/radiusward-node}"
export RADIUSWARD_GATEWAY_AERON_DIR="${RADIUSWARD_GATEWAY_AERON_DIR:-/dev/shm/radiusward-gateway}"
export RADIUSWARD_DICTIONARY_DIR="${RADIUSWARD_DICTIONARY_DIR:-/etc/radiusward/dictionary.d}"
export RADIUSWARD_MANAGEMENT_HTTP_HOST="${RADIUSWARD_MANAGEMENT_HTTP_HOST:-0.0.0.0}"

# shellcheck disable=SC2086
exec java \
    -Xms$heap -Xmx$heap \
    -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -Xss512k \
    -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError \
    ${JAVA_OPTS:-} \
    -jar /opt/radiusward/radiusward.jar "$@"
