#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
name=gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu
sha=1e33d53dea59c8de823bbdfe0798280bdcd138636c7060da9d77a97ded095a84
archive="$WORK/$name.tar.xz"
for base in 'https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel' 'https://sources.buildroot.net/toolchain-external-arm-aarch64'; do
  if curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 "$base/$name.tar.xz" -o "$archive"; then
    printf '%s  %s\n' "$sha" "$archive" | sha256sum --check --strict
    printf '%s/%s.tar.xz\n' "$base" "$name" > "$WORK/sdk-source"
    break
  fi
done
test -s "$WORK/sdk-source"
mkdir "$WORK/armgnu103"
tar -xJf "$archive" -C "$WORK/armgnu103" --strip-components=1
python3 "$ROOT/scripts/phase2b.py" sdk
