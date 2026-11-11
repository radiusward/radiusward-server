#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# The prebuilt test images (docs/testing/strategy.md#test-images): eapol_test, radsecproxy, Samba AD, the bases of
# the Linux fault-injection and systemd images and the interop tests' server packages, all in the public package
# ghcr.io/radiusward/radiusward-test-images, tagged <image>-<hash>. The hash covers the image's inputs (testing/test-images/images.txt), so a changed Dockerfile
# gets a new tag and tests never pull an image built from other inputs.
#
#   scripts/test-images.sh list                 # the images
#   scripts/test-images.sh tag <image>          # <image>-<hash>
#   scripts/test-images.sh ref <image>          # the registry image if it exists, else builds it here; prints the ref
#   scripts/test-images.sh build <image> [--push]   # build (with --push: its platforms with buildx, and <image>-latest)
set -euo pipefail

root=${TEST_IMAGES_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
repository=${TEST_IMAGES_REPOSITORY:-ghcr.io/radiusward/radiusward-test-images}
definitions="$root/testing/test-images/images.txt"

definition() { # <image> → "context dockerfile inputs..."
  local line
  line=$(grep -E "^$1[[:space:]]" "$definitions" || true)
  [[ -n "$line" ]] || { echo "unknown test image: $1 (see $definitions)" >&2; exit 64; }
  echo "${line#* }"
}

inputs() { # <image> → the input files, repository-relative, sorted bytewise
  local -a def
  read -r -a def <<<"$(definition "$1")"
  local p
  for p in "${def[@]:2}"; do
    if [[ "$p" == *=* ]]; then
      continue
    elif [[ -d "$root/$p" ]]; then
      (cd "$root" && find "$p" -type f ! -name '*.md')
    else
      echo "$p"
    fi
  done | LC_ALL=C sort -u
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }

# sha256 over, for each input in order: its path, a NUL byte, its content, a NUL byte; the first 12 hex digits
hash() {
  local f
  inputs "$1" | while IFS= read -r f; do
    printf '%s\0' "$f"
    cat "$root/$f"
    printf '\0'
  done | sha256 | cut -c1-12
}

tag() { echo "$1-$(hash "$1")"; }

platforms() { # <image> → the platforms to publish
  local -a def
  read -r -a def <<<"$(definition "$1")"
  local p
  for p in "${def[@]:2}"; do
    [[ "$p" == platforms=* ]] && { echo "${p#platforms=}"; return; }
  done
  echo linux/amd64,linux/arm64
}

exists() { docker manifest inspect "$repository:$1" >/dev/null 2>&1; }

build() {
  local image=$1 push=${2:-} t
  t=$(tag "$image")
  local -a def
  read -r -a def <<<"$(definition "$image")"
  local context="$root/${def[0]}" dockerfile="$root/${def[1]}"
  local -a labels=(--label "org.opencontainers.image.source=https://github.com/radiusward/radiusward-server"
    --label "org.opencontainers.image.description=radiusward test image $image (tests only, never production)"
    --label "org.opencontainers.image.licenses=Apache-2.0")
  if [[ "$push" == "--push" ]]; then
    if exists "$t"; then
      echo "$repository:$t exists; refreshing $image-latest only"
      docker buildx imagetools create -t "$repository:$image-latest" "$repository:$t"
      return
    fi
    docker buildx build --platform "$(platforms "$image")" -f "$dockerfile" "${labels[@]}" \
      -t "$repository:$t" -t "$repository:$image-latest" --push "$context"
  else
    docker build -q -f "$dockerfile" "${labels[@]}" -t "$repository:$t" "$context" >/dev/null
    echo "$repository:$t"
  fi
}

case "${1:-}" in
  list) grep -vE '^(#|[[:space:]]*$)' "$definitions" | awk '{print $1}' ;;
  tag) tag "${2:?image}" ;;
  hash) hash "${2:?image}" ;;
  inputs) inputs "${2:?image}" ;;
  platforms) platforms "${2:?image}" ;;
  ref)
    t=$(tag "${2:?image}")
    if docker image inspect "$repository:$t" >/dev/null 2>&1 || docker pull -q "$repository:$t" >/dev/null 2>&1; then
      echo "$repository:$t"
    else
      echo "$repository:$t not published: building it here" >&2
      build "$2"
    fi
    ;;
  build) build "${2:?image}" "${3:-}" ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 64 ;;
esac
