#!/bin/sh
# Builds the browser verifier (wasm/, every check of package verifier) to WebAssembly, reproducibly:
#   scripts/build-wasm.sh [out.wasm]      # default: wasm/verifier.wasm
# Pinned Go from mise.toml (or whatever `go` is on PATH when mise isn't installed: use the same version).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$root/wasm/verifier.wasm"}
case $out in /*) ;; *) out="$PWD/$out" ;; esac
go() { if command -v mise >/dev/null 2>&1; then mise exec -C "$root" -- go "$@"; else command go "$@"; fi; }
mkdir -p "$(dirname "$out")"
GOOS=js GOARCH=wasm CGO_ENABLED=0 GOFLAGS=-mod=readonly go -C "$root/wasm" build -trimpath -buildvcs=false \
  -ldflags="-s -w" -o "$out" .
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" "$(dirname "$out")/wasm_exec.js"
chmod 644 "$out" "$(dirname "$out")/wasm_exec.js"
echo "$(basename "$out"): $(wc -c < "$out" | tr -d ' ') bytes, sha256 $(shasum -a 256 "$out" | cut -d' ' -f1)"
