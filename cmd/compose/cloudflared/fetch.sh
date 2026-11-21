#!/bin/sh
# Fetches cloudflared's source at the pinned upstream commit (not a tag: a tag can be moved) and applies Tacy's
# patch, for build.sh. Needs git and network (GitHub). Run it on a fresh, empty directory:
#
#   sh cmd/compose/cloudflared/fetch.sh DIR      ->  DIR/src (cloudflared 2026.10.7 + tacy2, checked)
set -eu
commit=872b241f94871665c1c157adefcf90c11f0ead96 # cloudflared 2026.10.7
patch=cloudflared-2026.10.7-tacy2.patch
here=$(cd "$(dirname "$0")" && pwd)
out=$(cd "$1" && pwd)
[ ! -e "$out/src" ] || { echo "fetch.sh: $out/src exists (use a fresh directory)" >&2; exit 1; }
git init -q "$out/src"
git -C "$out/src" fetch -q --depth 1 https://github.com/cloudflare/cloudflared.git "$commit"
git -C "$out/src" -c advice.detachedHead=false checkout -q FETCH_HEAD
got=$(git -C "$out/src" rev-parse HEAD)
[ "$got" = "$commit" ] || { echo "fetch.sh: fetched $got, the pin is $commit" >&2; exit 1; }
git -C "$out/src" apply "$here/$patch"
echo "cloudflared $commit + $patch in $out/src"
