#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# The benchmark on Amazon ECS (docs/plans/benchmarks.md, B4; docs/testing/benchmarks.md): deploys the generator stack
# (deploy/aws/bench/generators.yaml: VPC, NAT, results bucket, generator instances) and the radiusward ECS stack
# (deploy/aws/cloudformation/radiusward-ecs.yaml) into its private subnets, configures the gateways for the
# benchmark, runs scripts/bench.py on the first generator instance through SSM, copies the result here and deletes
# both stacks again — also after a failure or Ctrl-C, unless --keep.
#
#   aws sso login --profile <aws profile>
#   AWS_PROFILE=<aws profile> scripts/bench-aws.sh --profile small --region eu-central-1
#
# Options: --profile small|standard (radiusward's, default small), --region, --image (default the edge image),
# --commit (the scripts' commit on GitHub, default HEAD), --generators 2..4 (instances), --steps, --duration,
# --keep (leave the stacks running), --delete-only (delete what a --keep run left), --out (default testing/benchmarks/target/bench). Needs the AWS CLI and
# credentials; nothing else runs locally.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
profile=small
region=${AWS_REGION:-${AWS_DEFAULT_REGION:-}}
image=ghcr.io/radiusward/radiusward-server:edge
commit=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo main)
generators=2
steps=1000,2000,4000,8000,16000,32000
duration=60
keep=false
delete_only=false
out=$root/testing/benchmarks/target/bench

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile=$2; shift 2 ;;
    --region) region=$2; shift 2 ;;
    --image) image=$2; shift 2 ;;
    --commit) commit=$2; shift 2 ;;
    --generators) generators=$2; shift 2 ;;
    --steps) steps=$2; shift 2 ;;
    --duration) duration=$2; shift 2 ;;
    --keep) keep=true; shift ;;
    --delete-only) delete_only=true; shift ;;
    --out) out=$2; shift 2 ;;
    -h|--help) sed -n '4,18p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 64 ;;
  esac
done
[[ $profile == small || $profile == standard ]] || { echo "--profile small|standard" >&2; exit 64; }
[[ -n $region ]] || { echo "--region or AWS_REGION is needed" >&2; exit 64; }
export AWS_DEFAULT_REGION=$region AWS_PAGER=""

name=radiusward-bench-$profile
net=$name-generators
log() { echo "$(date +%H:%M:%S) $*"; }
output() { aws cloudformation describe-stacks --stack-name "$1" --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue" --output text; }

empty_bucket() { # every object and version, so the bucket can be deleted
  local bucket=$1
  aws s3api head-bucket --bucket "$bucket" 2>/dev/null || return 0
  aws s3 rm "s3://$bucket" --recursive --quiet || true
  local versions
  while versions=$(aws s3api list-object-versions --bucket "$bucket" --max-items 500 \
      --query '{Objects: [Versions, DeleteMarkers][][].{Key: Key, VersionId: VersionId}}' --output json) &&
      [[ $(jq '.Objects | length' <<<"$versions") -gt 0 ]]; do
    aws s3api delete-objects --bucket "$bucket" --delete "$versions" >/dev/null
  done
}

cleanup() {
  local status=$?
  if [[ $keep == true ]]; then
    log "--keep: stacks $name and $net stay; delete them with: $0 --region $region --profile $profile --delete-only"
    exit $status
  fi
  log "deleting the stacks"
  local backup
  backup=$(output "$name" BackupBucketName 2>/dev/null || true)
  aws cloudformation delete-stack --stack-name "$name" 2>/dev/null || true
  aws cloudformation wait stack-delete-complete --stack-name "$name" 2>/dev/null || log "  $name: delete not complete, check the console"
  # the backup bucket is kept by its DeletionPolicy (production data); the benchmark's is not
  if [[ -n $backup && $backup != None ]]; then empty_bucket "$backup"; aws s3api delete-bucket --bucket "$backup" 2>/dev/null || true; fi
  empty_bucket "$(output "$net" ResultsBucket 2>/dev/null || true)"
  aws cloudformation delete-stack --stack-name "$net" 2>/dev/null || true
  aws cloudformation wait stack-delete-complete --stack-name "$net" 2>/dev/null || log "  $net: delete not complete, check the console"
  log "deleted"
  exit $status
}

command -v aws >/dev/null && command -v jq >/dev/null || { echo "needs the AWS CLI and jq" >&2; exit 69; }
aws sts get-caller-identity --query Account --output text >/dev/null
trap cleanup EXIT
trap 'exit 130' INT TERM
[[ $delete_only == true ]] && exit 0

log "generator stack $net ($generators × generators, $region)"
aws cloudformation deploy --stack-name "$net" --template-file "$root/deploy/aws/bench/generators.yaml" \
    --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
    --parameter-overrides GeneratorCount="$generators" Image="$image"
vpc=$(output "$net" VpcId); cidr=$(output "$net" VpcCidr)
subnets=$(output "$net" PrivateSubnetIds); zones=$(output "$net" AvailabilityZones)
bucket=$(output "$net" ResultsBucket); controller=$(output "$net" Controller); others=$(output "$net" Generators)

log "radiusward stack $name (profile $profile, $image)"
aws cloudformation deploy --stack-name "$name" --template-file "$root/deploy/aws/cloudformation/radiusward-ecs.yaml" \
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --no-fail-on-empty-changeset \
    --parameter-overrides VpcId="$vpc" VpcCidr="$cidr" MemberSubnetIds="$subnets" MemberAvailabilityZones="$zones" \
        GatewaySubnetIds="$subnets" LoadBalancerScheme=internal NasCidr="$cidr" Image="$image" Profile="$profile" \
        Namespace="$name.local"
cluster=$(output "$name" ClusterName)
gateways="$(output "$name" Gateway0Address),$(output "$name" Gateway1Address)"

log "configuring the gateways for the benchmark"
secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
aws secretsmanager put-secret-value --secret-id "$(output "$name" NasSecretArn)" --secret-string "$secret" >/dev/null
aws secretsmanager put-secret-value --secret-id "$(output "$name" GatewayUsersSecretArn)" \
    --secret-string 'load Cleartext-Password := "load"' >/dev/null
aws ssm put-parameter --overwrite --name "$(output "$name" GatewayConfigParameter)" --type String --value "$(cat <<EOF
# benchmark (scripts/bench-aws.sh): NAS entry for the generator subnets, the load user of radclient
nas.bench.address=$cidr
nas.bench.secret=\${env:NAS_SECRET}
nas.bench.id=1001
gateway.auth.enabled=true
gateway.auth.port=1812
auth.stores=bench
auth.store.bench.type=file
auth.store.bench.path=/tmp/users
auth.store.bench.chap=true
auth.store.bench.mschap=true
EOF
)" >/dev/null
for id in 0 1; do
  aws ecs update-service --cluster "$cluster" --service "gateway-$id" --force-new-deployment >/dev/null
done
for attempt in 1 2 3; do  # each wait gives up after 10 minutes
  aws ecs wait services-stable --cluster "$cluster" --services node-0 node-1 node-2 gateway-0 gateway-1 && break
  [[ $attempt == 3 ]] && { log "the services did not become stable"; exit 1; }
done

log "waiting for the generators"
for instance in $controller ${others//,/ }; do
  until [[ $(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$instance" \
      --query 'length(InstanceInformationList)' --output text) == 1 ]]; do sleep 10; done
done

member_type=$(aws cloudformation describe-stack-resource --stack-name "$name" --logical-resource-id MemberLaunchTemplate \
    --query StackResourceDetail.PhysicalResourceId --output text | xargs -I{} aws ec2 describe-launch-template-versions \
    --launch-template-id {} --versions '$Latest' --query 'LaunchTemplateVersions[0].LaunchTemplateData.InstanceType' --output text)
generator_type=$(aws ec2 describe-instances --instance-ids "$controller" --query 'Reservations[0].Instances[0].InstanceType' --output text)
remote_hosts=local${others:+,$others}
script=$(cat <<EOF
set -u
until [ -f /var/lib/radiusward-bench-ready ]; do sleep 5; done
rm -rf /opt/radiusward && git init -q /opt/radiusward && cd /opt/radiusward
git fetch -q --depth 1 https://github.com/radiusward/radiusward-server.git $commit && git checkout -q FETCH_HEAD
export AWS_DEFAULT_REGION=$region RADIUSWARD_PROFILE=$profile
python3 scripts/bench.py --target $gateways --ecs-cluster $cluster --generator-hosts $remote_hosts \
    --secret $secret --image $image --where aws-$profile --steps $steps --duration $duration \
    --label region=$region --label member_instance=$member_type --label generator_instance=$generator_type \
    --label generators=$generators --out /tmp/bench > /tmp/bench.log 2>&1
status=\$?
aws s3 cp /tmp/bench.log s3://$bucket/bench.log --quiet
for f in /tmp/bench/bench-*.json; do [ -f "\$f" ] && aws s3 cp "\$f" s3://$bucket/ --quiet; done
tail -n 25 /tmp/bench.log
exit \$status
EOF
)
log "benchmark on $controller (generators: $remote_hosts)"
command_id=$(aws ssm send-command --instance-ids "$controller" --document-name AWS-RunShellScript \
    --parameters "$(jq -n --arg c "$script" '{commands: [$c], executionTimeout: ["14400"]}')" \
    --query Command.CommandId --output text)
while :; do
  sleep 30
  state=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$controller" \
      --query Status --output text 2>/dev/null || echo Pending)
  case $state in
    Pending|InProgress|Delayed) ;;
    *) break ;;
  esac
done
aws ssm get-command-invocation --command-id "$command_id" --instance-id "$controller" \
    --query StandardOutputContent --output text
mkdir -p "$out"
aws s3 cp "s3://$bucket/" "$out/" --recursive --exclude '*' --include 'bench-*.json' --include bench.log --quiet
log "benchmark: $state; results in $out"
[[ $state == Success ]]
