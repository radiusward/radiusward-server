#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Restores every member of a Helm release from its cluster backup after a lost quorum (ADR 0065,
# docs/operations/backup.md). Stops the members and the backup, copies the backup out through a temporary pod, gives
# each member an empty volume, restores it from the copy with `radiusward cluster-restore` in a temporary pod, and
# starts the members and the backup again. Every step mounts one volume at a time, so it works with node-local
# volumes too. Needs kubectl, tar and python3.
#
#   scripts/k8s-restore.sh -n <namespace> -r <release> [--context <kube context>] [--keep <dir>]
set -euo pipefail

ns="" release="" context="" keep=""
while (($#)); do
  case "$1" in
    -n) ns=$2; shift 2 ;;
    -r) release=$2; shift 2 ;;
    --context) context=$2; shift 2 ;;
    --keep) keep=$2; shift 2 ;;
    *) echo "usage: $0 -n <namespace> -r <release> [--context <ctx>] [--keep <dir>]" >&2; exit 64 ;;
  esac
done
[[ -n "$ns" && -n "$release" ]] || { echo "usage: $0 -n <namespace> -r <release>" >&2; exit 64; }

fn="$release-radiusward"
k() { kubectl ${context:+--context "$context"} -n "$ns" "$@"; }
log() { printf '%s %s\n' "$(date +%T)" "$*"; }
copy=${keep:-$(mktemp -d)}
mkdir -p "$copy"

image=$(k get statefulset "$fn-node" -o jsonpath='{.spec.template.spec.containers[0].image}')
pull=$(k get statefulset "$fn-node" -o jsonpath='{.spec.template.spec.containers[0].imagePullPolicy}')

# toolbox <name> <claim> [env-json] [node]: a pod that mounts one claim at /var/lib/radiusward and waits; on <node>
# when given, so a node-local volume is created where its member will run
toolbox() {
  local name=$1 claim=$2 env=${3:-[]} node=${4:-}
  local placement=""
  # a node selector, not nodeName: the scheduler must place the pod so a WaitForFirstConsumer volume is provisioned
  [[ -n "$node" ]] && placement="\"nodeSelector\": {\"kubernetes.io/hostname\": \"$node\"},"

  k delete pod "$name" --ignore-not-found --wait >/dev/null
  k apply -f - >/dev/null <<EOF
{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "$name", "labels": {"app.kubernetes.io/component": "restore"}},
 "spec": {$placement "restartPolicy": "Never",
  "securityContext": {"runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001},
  "containers": [{"name": "restore", "image": "$image", "imagePullPolicy": "$pull",
    "command": ["sleep", "3600"], "env": $env,
    "volumeMounts": [{"name": "data", "mountPath": "/var/lib/radiusward"},
                     {"name": "config", "mountPath": "/etc/radiusward/cluster.properties", "subPath": "cluster.properties"}]}],
  "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "$claim"}},
              {"name": "config", "configMap": {"name": "$fn-node"}}]}}
EOF
  k wait --for=condition=Ready "pod/$name" --timeout=180s >/dev/null
}

# where the members ran: their new volumes are made there (node-local volumes, anti-affinity between members)
declare -a nodes=()
for i in 0 1 2; do
  nodes[i]=$(k get pod "$fn-node-$i" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)
done
if [[ -z "${nodes[0]}${nodes[1]}${nodes[2]}" ]]; then # already gone: three distinct worker nodes, if there are
  read -r -a spare <<<"$(kubectl ${context:+--context "$context"} get nodes -l '!node-role.kubernetes.io/control-plane' \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')"
  if ((${#spare[@]} >= 3)); then nodes=("${spare[0]}" "${spare[1]}" "${spare[2]}"); fi
fi

log "stopping the members and the backup of $fn"
k scale statefulset "$fn-node" --replicas=0 >/dev/null
k scale statefulset "$fn-backup" --replicas=0 >/dev/null
k wait --for=delete pod -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component in (node,backup)" \
  --timeout=180s >/dev/null 2>&1 || true

log "copying the backup out to $copy"
toolbox "$fn-restore-source" "data-$fn-backup-0"
k exec "$fn-restore-source" -- tar czf - -C /var/lib/radiusward/backup . | tar xzf - -C "$copy" 2>/dev/null
k delete pod "$fn-restore-source" --wait >/dev/null
[[ -f "$copy/cluster/recording.log" ]] || { log "no backup in data-$fn-backup-0"; exit 1; }

template=$(k get statefulset "$fn-node" -o json | python3 -c '
import json, sys
t = json.load(sys.stdin)["spec"]["volumeClaimTemplates"][0]
print(json.dumps(t["spec"]))')

for i in 0 1 2; do
  claim="data-$fn-node-$i"
  log "member $i: a new empty volume ($claim)"
  k delete pvc "$claim" --ignore-not-found --wait >/dev/null
  k apply -f - >/dev/null <<EOF
{"apiVersion": "v1", "kind": "PersistentVolumeClaim",
 "metadata": {"name": "$claim", "labels": {"app.kubernetes.io/instance": "$release"}}, "spec": $template}
EOF
  toolbox "$fn-restore-$i" "$claim" "[{\"name\": \"RADIUSWARD_CLUSTER_NODE_ID\", \"value\": \"$i\"}]" "${nodes[i]:-}"
  k exec "$fn-restore-$i" -- mkdir -p /tmp/backup
  # COPYFILE_DISABLE and no xattrs: macOS tar would add ._* files that a member cannot read
  COPYFILE_DISABLE=1 tar czf - --no-xattrs -C "$copy" . 2>/dev/null | k exec -i "$fn-restore-$i" -- tar xzf - -C /tmp/backup
  k exec "$fn-restore-$i" -- radiusward cluster-restore --from /tmp/backup \
    --config /etc/radiusward/cluster.properties 2>&1 | grep -v "SVE" | sed 's/^/  /'
  k delete pod "$fn-restore-$i" --wait >/dev/null
done

log "starting the members and the backup"
k scale statefulset "$fn-node" --replicas=3 >/dev/null
k rollout status statefulset "$fn-node" --timeout=600s >/dev/null
k scale statefulset "$fn-backup" --replicas=1 >/dev/null
log "restored: every member from the backup's snapshot and log"
[[ -z "$keep" ]] && rm -rf "$copy"
exit 0
