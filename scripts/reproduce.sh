#!/bin/sh
# Rebuilds a release from its tag and compares the result with the published release manifest (compose sha256,
# binary sha256s, image digests, commit, Go version, base image), then checks that ghcr.io serves exactly the
# rebuilt images, fetched anonymously by digest.
#   scripts/reproduce.sh v0.2.0            # in the pinned Go container the release builds in (needs docker)
#   scripts/reproduce.sh --native v0.2.0   # with this machine's Go (must be the pinned version; mise if installed)
# Needs git, curl and jq. Set TACY_REPO to check a fork. Releases before v0.2.0 (tacy-release/v1) have no images.
set -eu
native=""
if [ "${1:-}" = "--native" ]; then native=1; shift; fi
tag=${1:?usage: scripts/reproduce.sh [--native] vX.Y.Z}
repo=${TACY_REPO:-tacyhq/tacy}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" "https://github.com/$repo" "$work/src"
curl -fsSL "https://github.com/$repo/releases/download/$tag/release.json" -o "$work/release.json"
commit=$(git -C "$work/src" rev-parse HEAD)
oci=""
if grep -q '"oci"' "$work/src/cmd/compose/main.go"; then oci="--oci rebuilt-oci"; fi
if [ -n "$native" ]; then
  echo "rebuilding $repo $tag ($commit) natively"
  gocmd() { if command -v mise >/dev/null 2>&1; then mise trust -q "$work/src/mise.toml" && mise exec -C "$work/src" -- go "$@"; else command go "$@"; fi; }
  (cd "$work/src" && GOFLAGS=-mod=readonly gocmd run ./cmd/compose --check $oci --manifest rebuilt.json --version "$tag" --commit "$commit")
else
  image=$(grep -o 'golang:[^"]*@sha256:[0-9a-f]*' "$work/src/cmd/compose/main.go")
  echo "rebuilding $repo $tag ($commit) in $image"
  docker run --rm -v "$work/src:/src" -w /src -e GOFLAGS=-mod=readonly "$image" \
    go run ./cmd/compose --check $oci --manifest rebuilt.json --version "$tag" --commit "$commit"
fi
if ! diff "$work/release.json" "$work/src/rebuilt.json"; then
  echo "MISMATCH: the rebuild differs from the published release.json (diff above)"
  exit 1
fi
echo "REPRODUCED: the published release.json matches this rebuild"
if [ -n "$oci" ]; then
  # Each image the release names: its manifest from ghcr.io, without credentials, by digest, must hash to that
  # digest and be the rebuilt layout's manifest (so the config and layers it names are the rebuilt ones).
  jq -r '.images | to_entries[] | "\(.key) \(.value)"' "$work/release.json" | while read -r name ref; do
    r=${ref#ghcr.io/}; r=${r%@*}; digest=${ref#*@}
    tok=$(curl -fsS "https://ghcr.io/token?scope=repository:$r:pull&service=ghcr.io" | jq -er .token)
    curl -fsS -H "Authorization: Bearer $tok" -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "https://ghcr.io/v2/$r/manifests/$digest" -o "$work/served.json"
    served="sha256:$(shasum -a 256 "$work/served.json" | cut -d' ' -f1)"
    built="$work/src/rebuilt-oci/$name/blobs/sha256/${digest#sha256:}"
    if [ "$served" != "$digest" ] || ! cmp -s "$work/served.json" "$built"; then
      echo "MISMATCH: ghcr.io serves another manifest for $ref"
      exit 1
    fi
    echo "SERVED: $ref"
  done
fi
echo "Check the signature: gh attestation verify compose.yaml --repo $repo --signer-workflow $repo/.github/workflows/release.yml"
