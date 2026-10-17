#!/bin/sh
# Rebuilds a release from its tag, in the same pinned Go container the agent VM builds in, and compares the result
# with the published release manifest (compose sha256, binary sha256, commit, Go version).
#   scripts/reproduce.sh v0.1.0
# Needs git, curl and docker. Set TACY_REPO to check a fork.
set -eu
tag=${1:?usage: scripts/reproduce.sh vX.Y.Z}
repo=${TACY_REPO:-tacyhq/tacy}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" "https://github.com/$repo" "$work/src"
curl -fsSL "https://github.com/$repo/releases/download/$tag/release.json" -o "$work/release.json"
commit=$(git -C "$work/src" rev-parse HEAD)
image=$(grep -o 'golang:[^"]*@sha256:[0-9a-f]*' "$work/src/cmd/compose/main.go")
echo "rebuilding $repo $tag ($commit) in $image"
docker run --rm -v "$work/src:/src" -w /src -e GOFLAGS=-mod=readonly "$image" \
  go run ./cmd/compose --check --manifest rebuilt.json --version "$tag" --commit "$commit"
if diff "$work/release.json" "$work/src/rebuilt.json"; then
  echo "REPRODUCED: the published release.json matches this rebuild"
  echo "Check its signature: gh attestation verify compose.yaml --repo $repo --signer-workflow $repo/.github/workflows/release.yml"
else
  echo "MISMATCH: the rebuild differs from the published release.json (diff above)"
  exit 1
fi
