#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Runs a local radiusward cluster as separate JVMs on loopback (Phase 1, no Docker):
# three cluster nodes (ports 9000/9100/9200, management 9090-9092) and two gateways
# (RADIUS UDP 1813 and 1814, management 9190/9191). State and logs live in .local/.
#
#   scripts/run-local.sh build                 build radiusward.jar and radclient.jar
#   scripts/run-local.sh start [name...]       start everything, or node-0 node-1 node-2 gateway-a gateway-b
#   scripts/run-local.sh stop [name...]        graceful stop (SIGTERM)
#   scripts/run-local.sh kill <name>           kill -9, e.g. to simulate a crashed leader
#   scripts/run-local.sh restart <name>
#   scripts/run-local.sh status                processes, roles, applied counts, digests
#   scripts/run-local.sh logs <name>           follow a log
#   scripts/run-local.sh leader                print the current leader's name
#   scripts/run-local.sh demo-failover         load + kill -9 the leader + show that nothing was lost
#   scripts/run-local.sh clean                 stop everything and delete .local/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOCAL="$ROOT/.local"
CONFIG="$ROOT/config/local"
JAR="$ROOT/distribution/target/radiusward.jar"
RADCLIENT="$ROOT/tools/radclient/target/radclient.jar"
JAVA="${JAVA_HOME:+$JAVA_HOME/bin/}java"
# small profile memory budget (ADR 0004)
NODE_OPTS="-Xms384m -Xmx384m -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -Xss512k -XX:+UseG1GC"
GATEWAY_OPTS="-Xms192m -Xmx192m -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=48m -Xss512k -XX:+UseG1GC"
ALL=(node-0 node-1 node-2 gateway-a gateway-b)

mkdir -p "$LOCAL/logs" "$LOCAL/pids"

die() { echo "run-local: $*" >&2; exit 1; }

port_of() {
    case "$1" in
        node-0) echo 9090 ;; node-1) echo 9091 ;; node-2) echo 9092 ;;
        gateway-a) echo 9190 ;; gateway-b) echo 9191 ;;
        *) die "unknown component $1 (one of ${ALL[*]})" ;;
    esac
}

pid_of() {
    local f="$LOCAL/pids/$1.pid"
    [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null && cat "$f" || true
}

ensure_built() {
    [[ -f "$JAR" && -f "$RADCLIENT" ]] || build
}

build() {
    "$ROOT/mvnw" -q -B -pl distribution,tools/radclient -am package -DskipTests -Dspotless.check.skip=true -Djacoco.skip=true
}

start_one() {
    local name="$1" pid
    pid="$(pid_of "$name")"
    if [[ -n "$pid" ]]; then echo "$name already running (pid $pid)"; return; fi
    local args opts
    case "$name" in
        node-*)
            args=(cluster-node --config "$CONFIG/cluster.properties" --config "$CONFIG/$name.properties")
            opts="$NODE_OPTS" ;;
        gateway-*)
            args=(gateway --config "$CONFIG/$name.properties" --config "$CONFIG/nas-clients.properties")
            opts="$GATEWAY_OPTS" ;;
    esac
    # shellcheck disable=SC2086
    nohup "$JAVA" $opts -jar "$JAR" "${args[@]}" >>"$LOCAL/logs/$name.log" 2>&1 &
    echo $! >"$LOCAL/pids/$name.pid"
    disown $! 2>/dev/null || true
    echo "started $name (pid $!, log .local/logs/$name.log)"
}

stop_one() {
    local name="$1" pid
    pid="$(pid_of "$name")"
    [[ -z "$pid" ]] && { echo "$name not running"; return; }
    kill "$pid"
    for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
    rm -f "$LOCAL/pids/$name.pid"
    echo "stopped $name"
}

kill_one() {
    local name="$1" pid
    pid="$(pid_of "$name")"
    [[ -z "$pid" ]] && die "$name not running"
    kill -9 "$pid"
    rm -f "$LOCAL/pids/$name.pid"
    echo "killed $name (kill -9, pid $pid)"
}

state() { curl -s --max-time 1 "http://127.0.0.1:$(port_of "$1")/state" || true; }

field() { # crude JSON field extraction, enough for status output
    sed -n "s/.*\"$2\":\"\{0,1\}\([^,\"}]*\)\"\{0,1\}.*/\1/p" <<<"$1"
}

status() {
    printf "%-10s %-8s %-10s %-9s %-11s %s\n" NAME PID ROLE APPLIED DUPLICATES DIGEST/STATE
    for name in "${ALL[@]}"; do
        local pid s
        pid="$(pid_of "$name")"
        s="$(state "$name")"
        if [[ "$name" == node-* ]]; then
            printf "%-10s %-8s %-10s %-9s %-11s %s\n" "$name" "${pid:--}" "$(field "$s" role)" \
                "$(field "$s" applied)" "$(field "$s" duplicates)" "$(field "$s" stateDigest)"
        else
            printf "%-10s %-8s %-10s %-9s %-11s %s\n" "$name" "${pid:--}" "gateway" \
                "$(field "$s" committed)" "$(field "$s" duplicates)" "connected=$(field "$s" connected)"
        fi
    done
}

leader() {
    for name in node-0 node-1 node-2; do
        [[ "$(field "$(state "$name")" role)" == "LEADER" ]] && { echo "$name"; return; }
    done
    return 1
}

wait_ready() {
    local name="$1"
    for _ in $(seq 1 150); do
        curl -sf --max-time 1 "http://127.0.0.1:$(port_of "$name")/ready" >/dev/null && return 0
        sleep 0.2
    done
    die "$name not ready (see .local/logs/$name.log)"
}

demo_failover() {
    ensure_built
    for name in "${ALL[@]}"; do start_one "$name"; done
    for name in "${ALL[@]}"; do wait_ready "$name"; done
    echo; echo "== cluster ready"; status
    local acks="$LOCAL/demo-acks.csv"
    echo; echo "== load: 20 NAS x 50 sessions, 1000 req/s for 30s through both gateways (ack log: .local/demo-acks.csv)"
    "$JAVA" -jar "$RADCLIENT" load --server 127.0.0.1:1813,127.0.0.1:1814 --secret testing123 \
        --nas 20 --sessions 1000 --rate 1000 --duration 30s --interim 5s --ack-log "$acks" &
    local load=$!
    sleep 10
    local l
    l="$(leader)" || die "no leader"
    echo; echo "== t=10s: kill -9 the leader ($l)"
    kill_one "$l"
    wait "$load" || true
    echo; echo "== after failover"
    sleep 2
    status
    echo
    echo "Every acknowledged event is in the cluster state if APPLIED on the surviving nodes covers the"
    echo "acked events in the summary above, and both surviving nodes show the same digest."
    echo "Restart the killed node with: scripts/run-local.sh start $l"
}

cmd="${1:-}"; shift || true
case "$cmd" in
    build) build ;;
    start) ensure_built; [[ $# -eq 0 ]] && set -- "${ALL[@]}"; for n in "$@"; do port_of "$n" >/dev/null; start_one "$n"; done ;;
    stop) [[ $# -eq 0 ]] && set -- gateway-a gateway-b node-0 node-1 node-2; for n in "$@"; do stop_one "$n"; done ;;
    kill) [[ $# -eq 1 ]] || die "usage: kill <name>"; kill_one "$1" ;;
    restart) [[ $# -eq 1 ]] || die "usage: restart <name>"; stop_one "$1"; start_one "$1" ;;
    status) status ;;
    logs) [[ $# -eq 1 ]] || die "usage: logs <name>"; tail -f "$LOCAL/logs/$1.log" ;;
    leader) leader || die "no leader" ;;
    wait-ready) for n in "${@:-${ALL[@]}}"; do wait_ready "$n"; done ;;
    demo-failover) demo_failover ;;
    clean) for n in gateway-a gateway-b node-0 node-1 node-2; do stop_one "$n"; done; rm -rf "$LOCAL"; echo "removed .local/" ;;
    *) sed -n '4,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 64 ;;
esac
