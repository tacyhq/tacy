#!/bin/sh
# Builds Tacy's cloudflared from a tree fetch.sh made, reproducibly: the same bytes on any host (macOS or Linux,
# arm64 or amd64; checked against cmd/compose's ReleaseCloudflaredSHA256 by cmd/compose). Needs go (any version: the
# pinned toolchain is fetched through the Go module proxy and checked against the checksum database) and network for
# the modules (checked against cloudflared's go.sum). cmd/compose runs it; by hand:
#
#   sh cmd/compose/cloudflared/fetch.sh DIR && sh cmd/compose/cloudflared/build.sh DIR/src DIR/cloudflared
set -eu
src=$(cd "$1" && pwd)
out=$2
cd "$src"
GOTOOLCHAIN=go1.27.3 GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.Version=2026.10.7-tacy2 -X main.BuildTime=2026-10-30T17:05:00Z" \
  -o "$out" ./cmd/cloudflared
