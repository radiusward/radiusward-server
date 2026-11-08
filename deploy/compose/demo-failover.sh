#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Failover demo on the compose stack: ~2k requests/s through both gateways, kill -9 of the leader container
# after 10 s, then proof that every acknowledged event is in the replicated state.
#
#   deploy/compose/demo-failover.sh            (starts the stack if needed; leaves it running)
set -euo pipefail
cd "$(dirname "$0")"

compose() {
    if docker compose version >/dev/null 2>&1; then docker compose "$@"; else docker-compose "$@"; fi
}
members=172.28.0.10,172.28.0.11,172.28.0.12
secret=${NAS_SECRET:-testing123}

compose up -d --wait
tools=radiusward-demo-tools
docker rm -f "$tools" >/dev/null 2>&1 || true
compose run -d --name "$tools" --entrypoint sleep tools infinity >/dev/null
trap 'docker rm -f "$tools" >/dev/null 2>&1 || true' EXIT
tools_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$tools")

leader() {
    for i in 0 1 2; do
        if docker exec "$tools" radiusward probe "http://172.28.0.1$i:9090/state" 2>/dev/null \
                | grep -q '"role":"LEADER"'; then
            echo "node-$i"; return
        fi
    done
}

echo "load: 10,000 sessions, 2,000 requests/s for 25 s"
docker exec "$tools" radiusward radclient load --server 172.28.0.20:1813,172.28.0.21:1813 --secret "$secret" \
    --sessions 10000 --rate 2000 --duration 25s --interim 5s --retry-other-server --ack-log /tmp/acks.csv \
    > /tmp/radiusward-demo-load.txt 2>&1 &
load=$!
sleep 10
old=$(leader)
echo "kill -9 of the leader: $old"
docker kill -s KILL "$(compose ps -q "$old")" >/dev/null
sleep 3
echo "new leader: $(leader)"
wait "$load" || true
grep '^load:' /tmp/radiusward-demo-load.txt

echo "verifying every acknowledged event against the replicated state..."
docker exec "$tools" radiusward admin verify-acks --members "$members" --egress-host "$tools_ip" \
    --ack-log /tmp/acks.csv --nas-id 1001 2>/dev/null | grep -E '^(sessions|lost)='
compose start "$old" >/dev/null
echo "$old restarted; it rejoins as a follower and catches up"
