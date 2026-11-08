#!/bin/sh
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
# TEST ONLY. With RADIUSWARD_TEST_LAZYFS=1: mount LazyFS at /lazy (backed by /disk) and keep radiusward's data
# there (/var/lib/radiusward is a VOLUME in the base image, so LazyFS gets its own mount point).
# "shell <command>" runs a shell command instead of radiusward.
set -eu
if [ "${RADIUSWARD_TEST_LAZYFS:-0}" = "1" ]; then
    mkdir -p /disk /lazy
    if ! mountpoint -q /lazy; then
        lazyfs /lazy --config-path /etc/lazyfs.toml -o allow_other -o modules=subdir -o subdir=/disk \
            > /tmp/lazyfs.log 2>&1 &
        for _ in $(seq 1 150); do mountpoint -q /lazy && break; sleep 0.1; done
        mountpoint -q /lazy || { echo "LazyFS did not mount"; cat /tmp/lazyfs.log; exit 1; }
    fi
    export RADIUSWARD_CLUSTER_DATA_DIR=/lazy
fi
if [ "${1:-}" = "shell" ]; then shift; exec sh -c "$*"; fi
exec /usr/local/bin/radiusward "$@"
