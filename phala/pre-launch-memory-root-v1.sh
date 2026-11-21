#!/bin/bash
# Tacy pre-launch v1: every container image in TD memory, never on the provider-keyed disk (the keys plan §11.2).
# dstack runs this as root before docker compose up, on every start of the app (a boot, and the guest agent
# watchdog's restarts). It prints no secret: there is none on this VM before unlockd runs.
set -euo pipefail
fail() { echo "tacy pre-launch: $*" >&2; exit 1; }
ondisk() { [ "$(stat -f -c %T "$1")" != tmpfs ]; }
[ "$(stat -f -c %T /run)" = tmpfs ] || fail "/run isn't tmpfs"
droot=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
croot=/var/lib/containerd
if ondisk "$droot" || { [ -d "$croot" ] && ondisk "$croot"; }; then
  echo "tacy pre-launch: moving the image stores into memory"
  systemctl stop docker.socket docker.service 2>/dev/null || true
  systemctl stop containerd.service 2>/dev/null || true
  for d in "$droot" "$croot"; do
    mkdir -p "$d"
    if ondisk "$d"; then mount -t tmpfs -o size=4g,mode=0711 tmpfs "$d"; fi
  done
  systemctl start containerd.service 2>/dev/null || true
  systemctl start docker.service
fi
for d in "$droot" "$croot"; do
  [ ! -d "$d" ] || ! ondisk "$d" || fail "$d is still on a disk"
done
[ "$(docker info -f '{{.DockerRootDir}}')" = "$droot" ] || fail "docker's data root moved"
install -d -m 0700 -o 10005 -g 10005 /run/tacy-unlock
printf 'boot=%s docker=%s containerd=%s fs=tmpfs\n' "$(cat /proc/sys/kernel/random/boot_id)" "$droot" "$croot" > /run/tacy-unlock/memory-root
chmod 0444 /run/tacy-unlock/memory-root
echo "tacy pre-launch: image stores in memory"
