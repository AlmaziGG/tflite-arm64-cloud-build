#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/qemu.log") 2>&1
sudo apt-get update
sudo apt-get install -y --no-install-recommends qemu-user
failed=0
for version in 15 14; do
  root="$WORK/ota/capsule$version/rootfs"
  if [[ ! -d "$root/lib" ]]; then
    echo "Capsule-$version QEMU: FAIL (rootfs missing: $root/lib)" >&2
    failed=1
    continue
  fi
  echo "Running ARM64 TFLite smoke test with Capsule-$version 44.90 userspace under QEMU"
  if qemu-aarch64 -L "$root" -U LD_PRELOAD -U LD_AUDIT -E "LD_LIBRARY_PATH=$ARTIFACTS" \
      "$ARTIFACTS/tflite_smoke" "$WORK/smoke-model.tflite"; then
    echo "Capsule-$version QEMU: PASS"
  else
    rc=$?
    echo "Capsule-$version QEMU: FAIL (exit=$rc)" >&2
    failed=1
  fi
done
(( failed == 0 )) || exit 1
echo 'PASS: QEMU userspace tests completed. This is not physical RK3308 validation.'
