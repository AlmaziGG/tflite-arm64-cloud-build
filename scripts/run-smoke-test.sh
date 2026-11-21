#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/qemu.log") 2>&1
for version in 15 14; do
  root="$WORK/ota/capsule$version/rootfs"
  [[ -d "$root/lib" ]] || { echo "Capsule-$version rootfs missing." >&2; exit 1; }
  echo "Running ARM64 TFLite smoke test with Capsule-$version 44.90 userspace under QEMU"
  qemu-aarch64 -L "$root" -U LD_PRELOAD -U LD_AUDIT -E "LD_LIBRARY_PATH=$ARTIFACTS" \
    "$ARTIFACTS/tflite_smoke" "$WORK/smoke-model.tflite"
done
echo 'PASS: QEMU userspace tests completed. This is not physical RK3308 validation.'
