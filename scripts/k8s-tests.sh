#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Kubernetes tests (Phase 4, ADR 0062/0063): a kind cluster with three workers, the Helm chart, and accounting plus
# Access-Request load from a pod while members and gateways are killed, rolled and replaced. A scenario fails when a
# request is lost (radclient's "failed" or Access-Request timeouts). Nightly in CI (k8s-tests.yml); needs Docker, kind,
# kubectl and helm.
#
#   scripts/k8s-tests.sh                 # build, create the cluster, run every scenario, delete the cluster
#   KEEP=1 scripts/k8s-tests.sh          # keep the cluster afterwards (kubectl --context kind-rw-k8s-test)
#   SKIP_BUILD=1 scripts/k8s-tests.sh    # use an image radiusward:k8s-test that is already built
#   scripts/k8s-tests.sh leader-kill     # only the named scenarios (baseline leader-kill member-roll gateway-roll replace-volume)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cluster=rw-k8s-test
ns=radiusward
release=rw
image=radiusward:k8s-test
out="$root/testing/k8s-tests/target"
scenarios=("${@:-baseline leader-kill member-roll gateway-roll replace-volume}")
read -r -a scenarios <<<"${scenarios[*]}"
failures=0

log() { printf '%s %s\n' "$(date +%T)" "$*"; }
k() { kubectl --context "kind-$cluster" -n "$ns" "$@"; }

cleanup() {
  mkdir -p "$out/logs"
  for pod in $(k get pods -o name 2>/dev/null); do
    k logs "$pod" --all-containers >"$out/logs/${pod#pod/}.log" 2>&1 || true
    k logs "$pod" --all-containers --previous >"$out/logs/${pod#pod/}.previous.log" 2>/dev/null || true
  done
  k get pods,pvc,svc -o wide >"$out/logs/resources.txt" 2>&1 || true
  if [[ -z "${KEEP:-}" ]]; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
}

build() {
  if [[ -n "${SKIP_BUILD:-}" ]]; then
    return
  fi
  log "building radiusward and the image $image"
  (cd "$root" && ./mvnw -B -ntp -q install -DskipTests -DskipITs -Djacoco.skip=true)
  docker build -q -f "$root/deploy/docker/Dockerfile" -t "$image" "$root" >/dev/null
}

create_cluster() {
  log "creating kind cluster $cluster (three workers)"
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  kind create cluster --name "$cluster" --wait 120s --config - >/dev/null 2>&1 <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
  - role: worker
  - role: worker
EOF
  kind load docker-image "$image" --name "$cluster" >/dev/null
}

install_chart() {
  log "installing the chart"
  helm --kube-context "kind-$cluster" install "$release" "$root/deploy/helm/radiusward" -n "$ns" --create-namespace \
    --wait --timeout 10m -f - >/dev/null <<EOF
image: {repository: ${image%%:*}, tag: ${image##*:}, pullPolicy: Never}
profile: small
node:
  persistence: {size: 2Gi, storageClass: standard}
  config: {archive.segment.length: 4m, log.purge.interval: 10s}
gateway:
  service: {type: ClusterIP}
  nas:
    - {name: pods, address: 10.244.0.0/16, secret: testing123, id: 1001}
  auth:
    enabled: true
    stores:
      - name: local
        type: file
        users: |
          load Cleartext-Password := "load"
        chap: true
        mschap: true
EOF
}

gateway_ip() { k get svc "$release-radiusward-gateway-$1" -o jsonpath='{.spec.clusterIP}'; }
member_ready() { k exec "$release-radiusward-node-$1" -- radiusward probe http://127.0.0.1:9090/ready 2>/dev/null; }
leader() { for i in 0 1 2; do member_ready "$i" | grep -q '"LEADER' && { echo "$i"; return; }; done; echo -1; }
follower() { local l; l=$(leader); echo $(((l + 1) % 3)); }

# start_load <seconds> [radclient load options]: accounting through both gateways, Access-Requests on top
start_load() {
  local seconds=$1
  shift
  k delete pod load --ignore-not-found --wait >/dev/null 2>&1
  k run load --image="$image" --image-pull-policy=Never --restart=Never \
    --overrides='{"spec":{"securityContext":{"runAsUser":10001}}}' -- radclient load \
    --server "$(gateway_ip 0):1813,$(gateway_ip 1):1813" --retry-other-server --secret testing123 --nas 5 \
    --duration "${seconds}s" --timeout 3s --retries 3 "$@" >/dev/null
  until [[ "$(k get pod load -o jsonpath='{.status.phase}')" == Running ]]; do sleep 1; done
}

# finish_load <scenario>: waits for the load pod and fails the scenario on a lost request
finish_load() {
  local phase summary access
  until phase=$(k get pod load -o jsonpath='{.status.phase}') && [[ "$phase" == Succeeded || "$phase" == Failed ]]; do
    sleep 3
  done
  summary=$(k logs load | grep '^load:' || true)
  access=$(k logs load | grep '^access:' || true)
  log "  $summary"
  [[ -n "$access" ]] && log "  $access"
  if ! grep -q 'failed 0,' <<<"$summary"; then
    fail "$1: accounting requests lost"
  elif [[ -n "$access" ]] && ! grep -q 'timeouts 0, unexpected 0' <<<"$access"; then
    fail "$1: Access-Requests lost or answered wrongly"
  else
    log "PASS $1"
  fi
}

fail() {
  log "FAIL $*"
  failures=$((failures + 1))
}

await_members_ready() {
  k rollout status statefulset/"$release-radiusward-node" --timeout=300s >/dev/null
  k rollout status statefulset/"$release-radiusward-gateway" --timeout=300s >/dev/null
}

scenario_baseline() {
  log "baseline: 60 s of load"
  start_load 60 --sessions 500 --rate 200 --interim 10s --access-rate 20
  finish_load baseline
}

scenario_leader-kill() {
  log "leader-kill: the leader's pod killed without grace under load"
  start_load 90 --sessions 500 --rate 200 --interim 10s --access-rate 20
  sleep 25
  local l
  l=$(leader)
  log "  killing member $l"
  k delete pod "$release-radiusward-node-$l" --grace-period=0 --force >/dev/null 2>&1
  finish_load leader-kill
  await_members_ready
}

scenario_member-roll() {
  log "member-roll: every member restarted in turn under load"
  start_load 150 --sessions 500 --rate 200 --interim 10s --access-rate 20
  sleep 10
  k rollout restart statefulset/"$release-radiusward-node" >/dev/null
  k rollout status statefulset/"$release-radiusward-node" --timeout=400s >/dev/null
  finish_load member-roll
}

scenario_gateway-roll() {
  log "gateway-roll: both gateways restarted in turn under load (NAS retry through the other)"
  start_load 120 --sessions 500 --rate 200 --interim 10s --access-rate 20
  sleep 10
  k rollout restart statefulset/"$release-radiusward-gateway" >/dev/null
  k rollout status statefulset/"$release-radiusward-gateway" --timeout=400s >/dev/null
  finish_load gateway-roll
}

snapshot() {
  local l
  l=$(leader)
  k exec "$release-radiusward-node-$l" -- radiusward cluster-tool "/var/lib/radiusward/node-$l/cluster" snapshot \
    2>&1 | grep -q "SNAPSHOT applied" || fail "replace-volume: snapshot on member $l"
}

log_start() {
  k exec "$release-radiusward-node-$1" -- radiusward probe http://127.0.0.1:9090/metrics 2>/dev/null |
    sed -n 's/^radiusward_log_start_bytes{[^}]*} \([0-9]*\).*/\1/p'
}

log_position() {
  k exec "$release-radiusward-node-$1" -- radiusward probe http://127.0.0.1:9090/metrics 2>/dev/null |
    sed -n 's/^radiusward_cluster_log_position_bytes{[^}]*} \([0-9]*\).*/\1/p'
}

scenario_replace-volume() {
  log "replace-volume: a member's volume deleted after the log was purged (ADR 0063)"
  for round in 1 2; do
    start_load 90 --sessions 2000 --rate 400 --interim 5s --first-session $((round * 100000))
    finish_load "replace-volume load $round"
    snapshot
  done
  local deadline=$((SECONDS + 120))
  until [[ "$(log_start 0)" -gt 0 && "$(log_start 1)" -gt 0 && "$(log_start 2)" -gt 0 ]]; do
    ((SECONDS < deadline)) || { fail "replace-volume: the log was not purged"; return; }
    sleep 5
  done
  local f
  f=$(follower)
  log "  log purged; deleting member $f's volume under load"
  start_load 90 --sessions 500 --rate 200 --interim 10s --access-rate 20 --first-session 900000
  sleep 5
  k delete pvc "data-$release-radiusward-node-$f" --wait=false >/dev/null
  k delete pod "$release-radiusward-node-$f" >/dev/null
  deadline=$((SECONDS + 180))
  until member_ready "$f" | grep -q '"UP"'; do
    ((SECONDS < deadline)) || { fail "replace-volume: member $f not ready after 180 s"; break; }
    sleep 3
  done
  k logs "$release-radiusward-node-$f" | grep ClusterSeed | sed 's/^/  /' || true
  finish_load replace-volume
  sleep 5
  local p0 p1 p2
  p0=$(log_position 0) p1=$(log_position 1) p2=$(log_position 2)
  if [[ "$p0" == "$p1" && "$p1" == "$p2" ]]; then
    log "PASS replace-volume: every member at log position $p0"
  else
    fail "replace-volume: log positions differ ($p0, $p1, $p2)"
  fi
}

mkdir -p "$out"
trap cleanup EXIT
build
create_cluster
install_chart
for s in "${scenarios[@]}"; do
  "scenario_$s"
done
log "$failures scenario(s) failed"
exit $((failures > 0))
