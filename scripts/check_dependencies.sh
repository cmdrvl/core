#!/usr/bin/env bash
# Dependency gate: this crate depends on exactly blake3, hmac, serde, serde_json and sha2.
#
#  1. No DIRECT dependency (normal or build, any target, any feature) outside those five. This
#     catches a new direct dependency even when the package is already in the tree transitively.
#  2. No PACKAGE in the runtime graph (normal edges, any target, any feature) that is not listed
#     in scripts/allowed-dependencies.txt.
#
# Any failure of `cargo tree` fails the gate, and so does an output that does not contain this
# crate (a gate that sees nothing must not pass).
set -euo pipefail

cd "$(dirname "$0")/.."
crate="cmdrvl-core"
approved="blake3 hmac serde serde_json sha2"
allowlist="scripts/allowed-dependencies.txt"
status=0

tree() {
  cargo tree --locked --target all --all-features --prefix none "$@"
}

names() {
  awk 'NF { print $1 }' | sort -u
}

direct="$(tree --edges normal,build --depth 1 | names)"
graph="$(tree --edges normal | names)"

for list in "$direct" "$graph"; do
  if ! grep -qx "$crate" <<<"$list"; then
    echo "dependency gate: cargo tree did not list $crate; refusing to pass" >&2
    exit 1
  fi
done

while read -r name; do
  [ "$name" = "$crate" ] && continue
  case " $approved " in
    *" $name "*) ;;
    *)
      echo "dependency gate: forbidden direct dependency: $name (approved: $approved)" >&2
      status=1
      ;;
  esac
done <<<"$direct"

allowed="$(grep -v '^[[:space:]]*#' "$allowlist" | awk 'NF { print $1 }')"
while read -r name; do
  if ! grep -qxF "$name" <<<"$allowed"; then
    echo "dependency gate: package not in $allowlist: $name" >&2
    status=1
  fi
done <<<"$graph"

if [ "$status" -eq 0 ]; then
  echo "dependency gate: ok ($(wc -l <<<"$graph" | tr -d ' ') packages, all allowed)"
fi
exit "$status"
