#!/usr/bin/env bash
# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# Refreshes the bundled FreeRADIUS RADIUS dictionaries from a pinned FreeRADIUS commit.
#
#   scripts/update-dictionaries.sh <freeradius-commit-sha>
#
# Rules (see docs/dictionaries.md and ADR 0008):
#   * only files carrying the CC BY 4.0 header are bundled; everything else is excluded
#   * $INCLUDE lines of excluded files are commented out in the root `dictionary`
#     (the only modification we make, recorded in the file header as CC BY 4.0 requires)
#   * every remaining $INCLUDE must resolve, otherwise the script fails
set -euo pipefail

SHA="${1:-}"
if [[ ! "$SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "usage: $0 <40-char freeradius-server commit sha>" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/radius-dictionary-freeradius"
DEST="$MODULE/src/main/resources/io/radiusward/radius/dictionary/freeradius"
LICENSE_HEADER="This work is licensed under CC-BY version 4.0"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading FreeRADIUS $SHA ..."
curl -sfL "https://codeload.github.com/FreeRADIUS/freeradius-server/tar.gz/$SHA" \
    | tar -xz -C "$WORK" --strip-components=3 "freeradius-server-$SHA/share/dictionary/radius"
SRC="$WORK/radius"
COMMIT_DATE="$(curl -sf "https://api.github.com/repos/FreeRADIUS/freeradius-server/commits/$SHA" \
    | sed -n 's/.*"date": *"\([^"]*\)".*/\1/p' | head -1)"

rm -rf "$DEST"
mkdir -p "$DEST"

excluded=()
for f in "$SRC"/dictionary*; do
    name="$(basename "$f")"
    if grep -q "$LICENSE_HEADER" "$f"; then
        cp "$f" "$DEST/$name"
    else
        excluded+=("$name")
    fi
done

if [[ ! -f "$DEST/dictionary" ]]; then
    echo "error: root dictionary missing or not CC BY 4.0 licensed" >&2
    exit 1
fi

# Comment out includes of excluded files and record the modification.
if ((${#excluded[@]} > 0)); then
    for name in "${excluded[@]}"; do
        sed -i.bak "s|^\(\$INCLUDE[[:space:]]*${name//./\\.}\)[[:space:]]*\$|# \1    # excluded by radiusward: no CC BY 4.0 header|" "$DEST/dictionary"
    done
    rm -f "$DEST/dictionary.bak"
    awk -v list="${excluded[*]}" 'NR==4 {print "# Modified by radiusward: $INCLUDE of " list " commented out (not CC BY 4.0 licensed)."} {print}' \
        "$DEST/dictionary" > "$WORK/root" && mv "$WORK/root" "$DEST/dictionary"
fi

# Every remaining $INCLUDE must resolve.
missing=0
while read -r inc; do
    if [[ ! -f "$DEST/$inc" ]]; then
        echo "error: unresolved \$INCLUDE $inc" >&2
        missing=1
    fi
done < <(grep -h '^\$INCLUDE' "$DEST"/dictionary* | awk '{print $2}')
((missing == 0)) || exit 1

count="$(find "$DEST" -name 'dictionary*' | wc -l | tr -d ' ')"
{
    echo "source=https://github.com/FreeRADIUS/freeradius-server/tree/$SHA/share/dictionary/radius"
    echo "commit=$SHA"
    echo "commitDate=$COMMIT_DATE"
    echo "files=$count"
    echo "excluded=${excluded[*]:-}"
    echo "license=CC-BY-4.0"
} > "$DEST/SOURCE.properties"

curl -sfL https://creativecommons.org/licenses/by/4.0/legalcode.txt -o "$MODULE/LICENSE-CC-BY-4.0.txt"
cp "$MODULE/LICENSE-CC-BY-4.0.txt" "$DEST/LICENSE-CC-BY-4.0.txt"

echo "Bundled $count dictionary files from $SHA ($COMMIT_DATE)."
if ((${#excluded[@]} > 0)); then
    echo "Excluded (no CC BY 4.0 header): ${excluded[*]}"
fi
