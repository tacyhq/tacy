#!/bin/sh
# Rebuilds a release from its tag and compares the result with the published release manifests (compose sha256,
# binary sha256s, image digests, commit, Go version, base image), then checks that ghcr.io serves exactly the
# rebuilt images, fetched anonymously by digest. An agent VM release (vX.Y.Z) has release.json, and since the key
# service is released (v0.21.0) also kms-release.json when its tag commits kms-compose.yaml; a key service release
# (kms-vX.Y.Z) has only kms-release.json.
#   scripts/reproduce.sh v0.2.0            # in the pinned Go container the release builds in (needs docker)
#   scripts/reproduce.sh --native v0.2.0   # with this machine's Go (must be the pinned version; mise if installed)
# Needs git, curl and jq. Set TACY_REPO to check a fork. Releases before v0.2.0 (tacy-release/v1) have no images.
# A release whose release.json has "gcp" (the Google Cloud files) is rebuilt with them: dstack's OS image is fetched
# by its pinned sha256, the three files are made again, and each published one must be byte for byte the rebuild.
# What can't be rebuilt: Google's firmware (the MRTDs) and its configuration (RTMR0 per shape). The script checks
# them the way the verifier does instead: each pinned MRTD must be in Google's signed launch endorsement, checked
# against Google's root compiled into the verifier (cmd/compose --gcp-endorsements), and prints what Google says the
# build is. RTMR0 stays a reviewed pin from observed boots (verifier.GCPBootMeasurements' Source).
# Set TACY_RELEASE_DIR to a directory holding the release's assets (release.json, gcp-*) to check those instead of
# downloading them from GitHub (a dry run of an unpublished release; TACY_REPO may then be a local path).
set -eu
native=""
if [ "${1:-}" = "--native" ]; then native=1; shift; fi
tag=${1:?usage: scripts/reproduce.sh [--native] vX.Y.Z | kms-vX.Y.Z}
repo=${TACY_REPO:-tacyhq/tacy}
case $tag in
  v[0-9]*) vm=1 ;;
  kms-v[0-9]*) vm="" ;;
  *) echo "not a release tag: $tag" >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
case $repo in /*) url=$repo ;; *) url="https://github.com/$repo" ;; esac
git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" "$url" "$work/src"
commit=$(git -C "$work/src" rev-parse HEAD)
kms=""
if [ -f "$work/src/kms-compose.yaml" ] && grep -q '"kms-release"' "$work/src/cmd/compose/main.go"; then kms=1; fi
[ -n "$vm" ] || [ -n "$kms" ] || { echo "$tag has no kms-compose.yaml" >&2; exit 1; }

# Releases with the tunnel (gatewayd's image carries our patched cloudflared): fetch cloudflared's source here, by its
# pinned upstream commit (cmd/compose/cloudflared/fetch.sh checks the commit and applies Tacy's patch), and have
# cmd/compose rebuild it from that source (TACY_CLOUDFLARED_FRESH: never a cached binary), so the gatewayd image's
# digest covers the rebuilt cloudflared.
cfd=""
if [ -n "$vm" ] && [ -f "$work/src/cmd/compose/cloudflared/fetch.sh" ]; then
  mkdir "$work/cfd"
  sh "$work/src/cmd/compose/cloudflared/fetch.sh" "$work/cfd"
  cfd=1
fi

# compose ARGS...: go run ./cmd/compose ARGS in the tag's source, natively or in the pinned Go container.
if [ -n "$native" ]; then
  if [ -n "$cfd" ]; then export TACY_CLOUDFLARED_SRC="$work/cfd/src" TACY_CLOUDFLARED_FRESH=1; fi
  echo "rebuilding $repo $tag ($commit) natively"
  gocmd() { if command -v mise >/dev/null 2>&1; then mise trust -q "$work/src/mise.toml" && mise exec -C "$work/src" -- go "$@"; else command go "$@"; fi; }
  compose() { (cd "$work/src" && GOFLAGS=-mod=readonly gocmd run ./cmd/compose "$@"); }
else
  image=$(grep -o 'golang:[^"]*@sha256:[0-9a-f]*' "$work/src/cmd/compose/main.go")
  echo "rebuilding $repo $tag ($commit) in $image"
  # The container runs as root: give what it writes back to this user (else the cleanup can't remove it).
  cfdargs=""
  if [ -n "$cfd" ]; then cfdargs="-v $work/cfd:/cfd -e TACY_CLOUDFLARED_SRC=/cfd/src -e TACY_CLOUDFLARED_FRESH=1"; fi
  compose() {
    # shellcheck disable=SC2086 # cfdargs and gcpenv are several words
    docker run --rm -v "$work/src:/src" $cfdargs ${gcpenv:-} -w /src -e GOFLAGS=-mod=readonly -e OWNER="$(id -u):$(id -g)" "$image" \
      sh -c 'go run ./cmd/compose "$@"; rc=$?; chown -R "$OWNER" rebuilt*.json rebuilt-oci* rebuilt-gcp dstack-gcp /cfd 2>/dev/null; exit $rc' sh "$@"
  }
fi

# served MANIFEST OCIDIR: each image MANIFEST names, its manifest from ghcr.io, without credentials, by digest, must
# hash to that digest and be the rebuilt layout's manifest (so the config and layers it names are the rebuilt ones).
# TACY_SERVED_REGISTRY (dry runs of an unpublished release only): check that registry instead of ghcr.io, by the
# same names and digests (an anonymous one such as ttl.sh/<random>; the result says so).
served() {
  jq -r '.images | to_entries[] | "\(.key) \(.value)"' "$1" | while read -r name ref; do
    r=${ref#ghcr.io/}; r=${r%@*}; digest=${ref#*@}
    if [ -n "${TACY_SERVED_REGISTRY:-}" ]; then
      host=${TACY_SERVED_REGISTRY%%/*} path=${TACY_SERVED_REGISTRY#*/}
      curl -fsS -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "https://$host/v2/$path/${r##*/}/manifests/$digest" -o "$work/served.json"
    else
    tok=$(curl -fsS "https://ghcr.io/token?scope=repository:$r:pull&service=ghcr.io" | jq -er .token)
    curl -fsS -H "Authorization: Bearer $tok" -H "Accept: application/vnd.oci.image.manifest.v1+json" \
      "https://ghcr.io/v2/$r/manifests/$digest" -o "$work/served.json"
    fi
    got="sha256:$(shasum -a 256 "$work/served.json" | cut -d' ' -f1)"
    built="$2/$name/blobs/sha256/${digest#sha256:}"
    if [ "$got" != "$digest" ] || ! cmp -s "$work/served.json" "$built"; then
      echo "${dry:-}MISMATCH: ghcr.io serves another manifest for $ref"
      exit 1
    fi
    echo "${dry:-}SERVED: $ref${TACY_SERVED_REGISTRY:+ (dry run: by $TACY_SERVED_REGISTRY)}"
  done
}

# asset NAME OUT: a release asset, from TACY_RELEASE_DIR (a dry run: every line it prints says so) or GitHub.
asset() {
  if [ -n "${TACY_RELEASE_DIR:-}" ]; then cp "$TACY_RELEASE_DIR/$1" "$2"
  else curl -fsSL "https://github.com/$repo/releases/download/$tag/$1" -o "$2"; fi
}
dry=""
if [ -n "${TACY_RELEASE_DIR:-}${TACY_SERVED_REGISTRY:-}" ]; then
  dry="DRY RUN "
  echo "DRY RUN: assets from ${TACY_RELEASE_DIR:-GitHub}, images from ${TACY_SERVED_REGISTRY:-ghcr.io}: not a check of a published release"
fi

if [ -n "$vm" ]; then
  asset release.json "$work/release.json"
  oci=""
  if grep -q '"oci"' "$work/src/cmd/compose/main.go"; then oci="--oci rebuilt-oci"; fi
  gcp=""
  if jq -e .gcp "$work/release.json" >/dev/null; then
    # dstack's tarball, by its pinned sha256 (the rebuild's own cmd/compose fetches and checks it).
    # dstack's tarball into the source tree (so the container sees it too), by its pinned sha256.
    name=$(basename "$(compose --gcp-fetch dstack-gcp | tail -1)")
    if [ -n "$native" ]; then export TACY_DSTACK_GCP_SRC="$work/src/dstack-gcp/$name"; else gcpenv="-e TACY_DSTACK_GCP_SRC=/src/dstack-gcp/$name"; fi
    gcp="--gcp-out rebuilt-gcp"
  fi
  # shellcheck disable=SC2086 # $oci and $gcp are two words or none
  compose --check $oci --manifest rebuilt.json --version "$tag" --commit "$commit" $gcp
  if ! diff "$work/release.json" "$work/src/rebuilt.json"; then
    echo "${dry:-}MISMATCH: the rebuild differs from the published release.json (diff above)"
    exit 1
  fi
  echo "${dry:-}REPRODUCED: the published release.json matches this rebuild"
  if [ -n "$cfd" ]; then echo "${dry:-}REPRODUCED: cloudflared $(git -C "$work/cfd/src" rev-parse HEAD) + Tacy's patch, rebuilt from source inside the gatewayd image"; fi
  if [ -n "$oci" ]; then served "$work/release.json" "$work/src/rebuilt-oci"; fi
  if [ -n "$gcp" ]; then
    for f in gcp-boot.tar.gz gcp-data.tar.gz gcp-sys-config.json; do
      asset "$f" "$work/$f"
      want=$(jq -r --arg f "$f" '.gcp.guest.files[$f]' "$work/release.json")
      got=$(shasum -a 256 "$work/$f" | cut -d' ' -f1)
      if [ "$got" != "$want" ] || ! cmp -s "$work/$f" "$work/src/rebuilt-gcp/$f"; then
        echo "${dry:-}MISMATCH: the published $f isn't the rebuild (sha256 $got, release.json $want)"
        exit 1
      fi
      echo "${dry:-}SERVED: $f sha256 $got (= the rebuild)"
    done
    echo "${dry:-}REPRODUCED: Google Cloud boot measurements from dstack $(jq -r .gcp.guest.dstack "$work/release.json")'s image: RTMR1 $(jq -r .gcp.guest.boot.rtmr1 "$work/release.json" | cut -c1-16)…, RTMR2 $(jq -r .gcp.guest.boot.rtmr2 "$work/release.json" | cut -c1-16)… (every boot set's)"
    echo "${dry:-}NOT REPRODUCIBLE (Google's): the firmware MRTDs and RTMR0 per shape; checked instead against Google's signed endorsement:"
    compose --gcp-endorsements rebuilt.json
  fi
fi
if [ -n "$kms" ]; then
  asset kms-release.json "$work/kms-release.json"
  compose --kms --kms-release --check --oci rebuilt-oci-kms --manifest rebuilt-kms.json --version "$tag" --commit "$commit"
  if ! diff "$work/kms-release.json" "$work/src/rebuilt-kms.json"; then
    echo "${dry:-}MISMATCH: the rebuild differs from the published kms-release.json (diff above)"
    exit 1
  fi
  echo "${dry:-}REPRODUCED: the published kms-release.json matches this rebuild"
  served "$work/kms-release.json" "$work/src/rebuilt-oci-kms"
fi
if [ -n "$vm" ]; then
  echo "Check the signature: gh attestation verify compose.yaml --repo $repo --signer-workflow $repo/.github/workflows/release.yml"
fi
if [ -n "$kms" ]; then
  echo "Check the signature: gh attestation verify kms-compose.yaml --repo $repo --signer-workflow $repo/.github/workflows/release.yml (and kms-app-compose.json)"
fi
