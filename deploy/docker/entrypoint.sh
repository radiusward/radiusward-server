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
    # session state lives off-heap (ADR 0004, 0036): ~240 bytes per session for the member and its exporter replica
    cluster-node:small)    heap=256m;  direct=576m ;;    # 2M sessions, measured (OverloadIT)
    cluster-node:standard) heap=768m;  direct=1536m ;;   # 5M sessions, estimated
    cluster-node:large)    heap=2g;    direct=5g ;;      # 20M sessions, estimated
    server:small)         heap=192m ;;
    server:standard)      heap=384m ;;
    server:large)         heap=768m ;;
    radclient:*)           heap=512m ;;
    cluster-backup:*)      heap=256m;  direct=256m ;;    # a media driver and an archive, no sessions (ADR 0065)
    admin:*)               heap=256m ;;   # verifiers keep the last event of every session of an ack log
    probe:*)               heap=32m; light=1 ;;   # health checks: small, starts fast, little memory next to the server
    *)                     heap=64m ;;    # version, cluster-tool
esac

# a short-lived tool commits its heap as it goes and skips the optimising compiler; the long-running ones commit theirs
# at start, so the container's limit is met at start and not under load
xms=$heap
gc=-XX:+UseG1GC
if [ -n "${light:-}" ]; then
    xms=8m
    gc="-XX:+UseSerialGC -XX:TieredStopAtLevel=1"
fi

# defaults for config keys (environment overrides beat properties files; see docs/configuration.md)
export RADIUSWARD_CLUSTER_DATA_DIR="${RADIUSWARD_CLUSTER_DATA_DIR:-/var/lib/radiusward}"
export RADIUSWARD_CLUSTER_AERON_DIR="${RADIUSWARD_CLUSTER_AERON_DIR:-/dev/shm/radiusward-node}"
export RADIUSWARD_SERVER_AERON_DIR="${RADIUSWARD_SERVER_AERON_DIR:-/dev/shm/radiusward-server}"
export RADIUSWARD_BACKUP_AERON_DIR="${RADIUSWARD_BACKUP_AERON_DIR:-/dev/shm/radiusward-backup}"
export RADIUSWARD_BACKUP_DATA_DIR="${RADIUSWARD_BACKUP_DATA_DIR:-/var/lib/radiusward/backup}"
export RADIUSWARD_DICTIONARY_DIR="${RADIUSWARD_DICTIONARY_DIR:-/etc/radiusward/dictionary.d}"
export RADIUSWARD_MANAGEMENT_HTTP_HOST="${RADIUSWARD_MANAGEMENT_HTTP_HOST:-0.0.0.0}"

# shellcheck disable=SC2086
exec java \
    -Xms$xms -Xmx$heap ${direct:+-XX:MaxDirectMemorySize=$direct} \
    -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -Xss512k \
    $gc -XX:+ExitOnOutOfMemoryError \
    ${JAVA_OPTS:-} \
    -jar /opt/radiusward/radiusward.jar "$@"
