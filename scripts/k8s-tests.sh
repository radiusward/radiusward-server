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
#   scripts/k8s-tests.sh leader-kill     # only the named scenarios (baseline leader-kill member-roll gateway-roll
#                                        # replace-volume restore-quorum loadbalancer; opt-in: scale)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cluster=rw-k8s-test
ns=radiusward
release=rw
image=radiusward:k8s-test
out="$root/testing/k8s-tests/target"
scenarios=("${@:-baseline loadbalancer leader-kill member-roll gateway-roll replace-volume restore-quorum}")
read -r -a scenarios <<<"${scenarios[*]}"
failures=0
# per scenario, for the JUnit XML the published test report reads (docs/plans/test-reports.md)
declare -a case_names=() case_seconds=() case_failures=() case_output=()
current="" current_start=0 current_failure="" current_output=""

log() {
  printf '%s %s\n' "$(date +%T)" "$*"
  current_output+="$(date +%T) $*"$'\n'
}

begin_case() {
  current=$1 current_start=$SECONDS current_failure="" current_output=""
}

end_case() {
  [[ -z "$current" ]] && return
  case_names+=("$current")
  case_seconds+=($((SECONDS - current_start)))
  case_failures+=("$current_failure")
  case_output+=("$current_output")
  current=""
}

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }

write_junit() {
  end_case
  local i n=${#case_names[@]} failed=0 total=0 file="$out/junit.xml"
  for ((i = 0; i < n; i++)); do
    total=$((total + case_seconds[i]))
    [[ -n "${case_failures[i]}" ]] && failed=$((failed + 1))
  done
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuite name="io.radiusward.k8s.KubernetesScenarios" tests="%d" failures="%d" errors="0" skipped="0" time="%d">\n' \
      "$n" "$failed" "$total"
    for ((i = 0; i < n; i++)); do
      printf '  <testcase classname="io.radiusward.k8s.KubernetesScenarios" name="%s" time="%d">\n' \
        "$(xml_escape "${case_names[i]}")" "${case_seconds[i]}"
      if [[ -n "${case_failures[i]}" ]]; then
        printf '    <failure message="%s"/>\n' "$(xml_escape "${case_failures[i]}")"
      fi
      printf '    <system-out>%s</system-out>\n' "$(xml_escape "${case_output[i]}")"
      printf '  </testcase>\n'
    done
    printf '</testsuite>\n'
  } >"$file"
}
k() { kubectl --context "kind-$cluster" -n "$ns" "$@"; }

cleanup() {
  local status=$?
  if [[ -n "$current" && $status -ne 0 && -z "$current_failure" ]]; then
    current_failure="aborted (exit status $status)" # a command of the scenario failed under set -e
  fi
  write_junit
  mkdir -p "$out/logs"
  for pod in $(k get pods -o name 2>/dev/null); do
    k logs "$pod" --all-containers >"$out/logs/${pod#pod/}.log" 2>&1 || true
    k logs "$pod" --all-containers --previous >"$out/logs/${pod#pod/}.previous.log" 2>/dev/null || true
  done
  k get pods,pvc,svc -o wide >"$out/logs/resources.txt" 2>&1 || true
  if [[ -z "${KEEP:-}" ]]; then
    docker rm -f "$cluster-nas" >/dev/null 2>&1 || true
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
  install_metallb
}

# MetalLB in L2 mode with addresses from kind's Docker network, so the gateways' LoadBalancer Services get addresses a
# container outside the cluster reaches, as a NAS reaches a real load balancer
metallb_version=v0.16.2
install_metallb() {
  log "installing MetalLB $metallb_version"
  local subnet base
  subnet=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | grep -m1 '\.')
  base=$(cut -d. -f1-2 <<<"$subnet")
  lb_range="$base.255.200-$base.255.250"
  # the NAS outside the cluster: a container on kind's network (kind's network has no user subnet, so Docker picks the
  # address); it waits, and the scenario runs radclient in it
  docker rm -f "$cluster-nas" >/dev/null 2>&1 || true
  docker run -d --name "$cluster-nas" --network kind --entrypoint sleep "$image" 86400 >/dev/null
  outside_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cluster-nas")
  kubectl --context "kind-$cluster" apply -f \
    "https://raw.githubusercontent.com/metallb/metallb/$metallb_version/config/manifests/metallb-native.yaml" >/dev/null
  kubectl --context "kind-$cluster" -n metallb-system wait --for=condition=Available deployment/controller \
    --timeout=180s >/dev/null
  kubectl --context "kind-$cluster" -n metallb-system wait --for=condition=Ready pod -l component=speaker \
    --timeout=180s >/dev/null
  local attempt
  for attempt in 1 2 3 4 5 6; do # the webhook takes a moment after the controller is available
    if kubectl --context "kind-$cluster" apply -f - >/dev/null 2>&1 <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata: {name: kind, namespace: metallb-system}
spec: {addresses: ["$lb_range"]}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata: {name: kind, namespace: metallb-system}
spec: {ipAddressPools: [kind]}
EOF
    then
      return
    fi
    sleep 10
  done
  log "MetalLB address pool not accepted"
  return 1
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
backup:
  persistence: {size: 2Gi, storageClass: standard}
  interval: 20s
gateway:
  service: {type: LoadBalancer, externalTrafficPolicy: Local}
  nas:
    - {name: pods, address: 10.244.0.0/16, secret: testing123, id: 1001}
    # the client outside the cluster, by its own address only: a rewritten source address would make it unknown
    - {name: outside, address: $outside_ip/32, secret: testing123, id: 1002}
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
  current_failure+="${current_failure:+; }$*"
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

backup_metric() {
  k exec "$release-radiusward-backup-0" -- radiusward probe http://127.0.0.1:9090/metrics 2>/dev/null |
    sed -n "s/^$1 \([0-9-]*\).*/\1/p"
}

applied() {
  k exec "$release-radiusward-node-$1" -- radiusward probe http://127.0.0.1:9090/state 2>/dev/null |
    grep -o '"applied":[0-9]*' | head -1 | cut -d: -f2
}

scenario_restore-quorum() {
  log "restore-quorum: every member's volume lost, the cluster restored from the backup (ADR 0065)"
  start_load 40 --sessions 500 --rate 200 --interim 10s --first-session 1500000 # events before the snapshot
  finish_load "restore-quorum load before the snapshot"
  snapshot
  start_load 20 --sessions 300 --rate 150 --interim 5s --first-session 1600000 # and after it: only the live log
  finish_load "restore-quorum load after the snapshot"
  local l position deadline
  l=$(leader)
  position=$(log_position "$l")
  deadline=$((SECONDS + 180))
  until k exec "$release-radiusward-backup-0" -- radiusward probe http://127.0.0.1:9090/ready 2>/dev/null |
    grep -q '"UP"' && [[ "$(backup_metric radiusward_backup_live_log_position_bytes)" -ge "$position" ]]; do
    ((SECONDS < deadline)) || { fail "restore-quorum: the backup did not catch up"; return; }
    sleep 5
  done
  local before
  before=$(applied "$l")
  log "  backup caught up (live log $(backup_metric radiusward_backup_live_log_position_bytes) >= $position);" \
    "$before events applied; deleting every member's volume"
  k scale statefulset "$release-radiusward-node" --replicas=0 >/dev/null
  k wait --for=delete pod -l "app.kubernetes.io/component=node" --timeout=180s >/dev/null 2>&1 || true
  for i in 0 1 2; do k delete pvc "data-$release-radiusward-node-$i" --wait >/dev/null; done
  "$root/scripts/k8s-restore.sh" -n "$ns" -r "$release" --context "kind-$cluster" | sed 's/^/  /'
  await_members_ready
  local i a ok=1
  for i in 0 1 2; do
    a=$(applied "$i")
    log "  member $i: $a events applied"
    [[ "$a" == "$before" ]] || ok=0
  done
  ((ok)) || { fail "restore-quorum: members restored with other counts than $before"; return; }
  start_load 30 --sessions 200 --rate 100 --interim 10s --first-session 2000000
  finish_load restore-quorum
}

# loadbalancer: a NAS outside the cluster (a container on kind's network) reaches both gateways through their
# LoadBalancer Services (MetalLB, externalTrafficPolicy: Local); its NAS entry is its own /32 address, so the
# source address must arrive unchanged. Accounting and Access-Requests, nothing lost, no unknown NAS.
scenario_loadbalancer() {
  log "loadbalancer: a NAS outside the cluster through the gateways' LoadBalancer addresses"
  local lb0="" lb1="" deadline=$((SECONDS + 120))
  until [[ -n "$lb0" && -n "$lb1" ]]; do
    lb0=$(k get svc "$release-radiusward-gateway-0" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    lb1=$(k get svc "$release-radiusward-gateway-1" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    ((SECONDS < deadline)) || { fail "loadbalancer: no LoadBalancer addresses"; return; }
    sleep 3
  done
  log "  gateways at $lb0 and $lb1; the NAS at $outside_ip"
  local before after out summary
  before=$(unknown_nas)
  out=$(docker exec "$cluster-nas" radiusward radclient auth --server "$lb0:1812" \
    --secret testing123 --user load --password load --method mschapv2 2>&1 | grep -E "Access-" | head -2 || true)
  log "  radclient auth: $(tr '\n' ' ' <<<"$out")"
  grep -q "Access-Accept" <<<"$out" || fail "loadbalancer: no Access-Accept from outside"
  summary=$(docker exec "$cluster-nas" radiusward radclient load \
    --server "$lb0:1813,$lb1:1813" --retry-other-server --secret testing123 --nas 5 --sessions 300 --rate 100 \
    --duration 60s --interim 10s --timeout 3s --retries 3 --access-rate 20 --first-session 3000000 2>&1 |
    grep -E '^(load|access):' || true)
  log "  $(grep '^load:' <<<"$summary")"
  log "  $(grep '^access:' <<<"$summary")"
  grep -q 'failed 0,' <<<"$summary" || fail "loadbalancer: accounting requests lost"
  grep -q 'timeouts 0, unexpected 0' <<<"$summary" || fail "loadbalancer: Access-Requests lost or answered wrongly"
  after=$(unknown_nas)
  if [[ "$after" != "$before" ]]; then
    fail "loadbalancer: $((after - before)) packets from an unknown NAS: the source address was rewritten"
  fi
  [[ -n "$current_failure" ]] || log "PASS loadbalancer: the source address arrived unchanged"
}

# packets of both gateways dropped as from an unknown NAS (accounting and authentication)
unknown_nas() {
  local g total=0 n
  for g in 0 1; do
    n=$(k exec "$release-radiusward-gateway-$g" -- radiusward probe http://127.0.0.1:9090/metrics 2>/dev/null |
      awk '/result="unknown_nas"/ {sum += $NF} END {print sum + 0}')
    total=$((total + n))
  done
  echo "$total"
}

# scale (4.9, opt-in: scripts/k8s-tests.sh scale): 500k sessions through both gateways from two load pods, with the
# Access-Request mix, while the leader is killed, a follower is cut off by a NetworkPolicy and a worker node is
# drained. Nothing may be lost; every session must be in the replicated state; no container may run out of memory.
scenario_scale() {
  log "scale: 500k sessions and Access-Requests while the leader is killed, a member cut off and a node drained"
  local g0 g1 seconds=${SCALE_SECONDS:-420} per=${SCALE_SESSIONS:-250000} rate=${SCALE_RATE:-1000}
  g0=$(gateway_ip 0) g1=$(gateway_ip 1)
  for p in a b; do k delete pod "load-$p" --ignore-not-found --wait >/dev/null 2>&1; done
  k run load-a --image="$image" --image-pull-policy=Never --restart=Never \
    --overrides='{"spec":{"securityContext":{"runAsUser":10001}}}' -- radclient load --server "$g0:1813,$g1:1813" \
    --retry-other-server --secret testing123 --nas 50 --sessions "$per" --rate "$rate" --duration "${seconds}s" \
    --interim 300s --no-stop --timeout 3s --retries 3 --access-rate 100 >/dev/null
  k run load-b --image="$image" --image-pull-policy=Never --restart=Never \
    --overrides='{"spec":{"securityContext":{"runAsUser":10001}}}' -- radclient load --server "$g1:1813,$g0:1813" \
    --retry-other-server --secret testing123 --nas 50 --sessions "$per" --rate "$rate" --duration "${seconds}s" \
    --interim 300s --no-stop --timeout 3s --retries 3 --access-rate 100 --first-session 10000000 >/dev/null
  local start=$SECONDS
  at() { while ((SECONDS - start < $1)); do sleep 2; done; }

  at 120
  local l
  l=$(leader)
  log "  +120 s: killing the leader, member $l"
  k delete pod "$release-radiusward-node-$l" --grace-period=0 --force >/dev/null 2>&1

  at 200
  local f
  f=$(follower)
  log "  +200 s: cutting member $f off for 30 s (NetworkPolicy)"
  printf '%s' "{\"apiVersion\": \"networking.k8s.io/v1\", \"kind\": \"NetworkPolicy\", \"metadata\": {\"name\": \"cut-off\"},
 \"spec\": {\"podSelector\": {\"matchLabels\": {\"statefulset.kubernetes.io/pod-name\": \"$release-radiusward-node-$f\"}},
          \"policyTypes\": [\"Ingress\", \"Egress\"]}}" | k apply -f - >/dev/null
  at 230
  k delete networkpolicy cut-off >/dev/null
  log "  +230 s: member $f reconnected"

  # the drain waits until every member is ready again: the members' PodDisruptionBudget refuses to evict while one
  # is still catching up from the cut-off (never two down), which held the first runs' drain back
  local m
  for m in 0 1 2; do
    until member_ready "$m" | grep -q '"UP"'; do sleep 2; done
  done
  at 260
  local victim node t0
  victim=$(follower)
  node=$(k get pod "$release-radiusward-node-$victim" -o jsonpath='{.spec.nodeName}')
  log "  +$((SECONDS - start)) s: draining $node (member $victim and what else runs there)"
  t0=$SECONDS
  if kubectl --context "kind-$cluster" drain "$node" --ignore-daemonsets --delete-emptydir-data --timeout=300s \
    >/dev/null 2>&1; then
    log "  drained in $((SECONDS - t0)) s"
  else
    fail "scale: the drain of $node did not complete within 300 s"
  fi
  sleep 20 # the member waits for its node (node-local volume); the gateway's NAS use the other one meanwhile
  kubectl --context "kind-$cluster" uncordon "$node" >/dev/null
  log "  +$((SECONDS - start)) s: $node uncordoned"
  local deadline=$((SECONDS + 180))
  until member_ready "$victim" | grep -q '"UP"'; do
    ((SECONDS < deadline)) || { fail "scale: member $victim not back after the drain"; break; }
    sleep 3
  done
  log "  +$((SECONDS - start)) s: member $victim back"

  local p phase summary access failed=0
  for p in a b; do
    until phase=$(k get pod "load-$p" -o jsonpath='{.status.phase}') && [[ "$phase" == Succeeded || "$phase" == Failed ]]; do
      sleep 5
    done
    summary=$(k logs "load-$p" | grep '^load:' || true)
    access=$(k logs "load-$p" | grep '^access:' || true)
    log "  load-$p: $summary"
    log "  load-$p: $access"
    grep -q 'failed 0,' <<<"$summary" || failed=1
    grep -q 'timeouts 0, unexpected 0' <<<"$access" || failed=1
  done
  ((failed)) && fail "scale: requests lost"
  await_members_ready
  sleep 10
  local i active
  for i in 0 1 2; do
    active=$(k exec "$release-radiusward-node-$i" -- radiusward probe http://127.0.0.1:9090/metrics 2>/dev/null |
      sed -n 's/^radiusward_sessions{[^}]*state="active"} \([0-9]*\).*/\1/p')
    log "  member $i: $active active sessions, log position $(log_position "$i")"
    [[ "$active" == $((2 * per)) ]] || fail "scale: member $i holds $active sessions, not $((2 * per))"
  done
  log "  restarts: $(k get pods -l "app.kubernetes.io/instance=$release" \
    -o jsonpath='{range .items[*]}{.metadata.name}={.status.containerStatuses[0].restartCount}/{.status.containerStatuses[0].lastState.terminated.reason}{" "}{end}')"
  if k get pods -l "app.kubernetes.io/instance=$release" \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[0].lastState.terminated.reason}{" "}{end}' | grep -q OOMKilled; then
    fail "scale: a container ran out of memory"
  fi
  [[ -n "$current_failure" ]] || log "PASS scale"
}

mkdir -p "$out"
trap cleanup EXIT
build
create_cluster
install_chart
for s in "${scenarios[@]}"; do
  end_case
  begin_case "$s"
  "scenario_$s"
done
log "$failures scenario(s) failed"
exit $((failures > 0))
