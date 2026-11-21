#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/smoke-abi.log") 2>&1

[[ -s "$ARTIFACTS/ota-rootfs-provenance.txt" ]] || { echo 'Verified OTA preparation provenance missing.' >&2; exit 1; }
[[ -s "$ARTIFACTS/tflite_smoke" && -s "$ARTIFACTS/libtensorflowlite_c.so" ]] || {
  echo 'Smoke executable or TFLite shared library is missing.' >&2
  exit 1
}
failed=0
for version in 15 14; do
  root="$WORK/ota/capsule$version/rootfs"
  report="$ARTIFACTS/elf-reports/capsule$version-smoke-abi.txt"
  [[ -d "$root" ]] || { echo "Capsule-$version rootfs missing." >&2; failed=1; continue; }
  echo "=== Strict smoke ABI audit: Capsule-$version OTA 44.90 ==="
  if python3 "$ROOT/scripts/verify_elf_abi.py" "$ARTIFACTS/tflite_smoke" "$root" \
      --allow-library "$ARTIFACTS/libtensorflowlite_c.so" 2>&1 | tee "$report"; then
    echo "Capsule-$version smoke ABI audit: PASS"
  else
    echo "Capsule-$version smoke ABI audit: FAIL" >&2
    failed=1
  fi
done
(( failed == 0 )) || exit 1
