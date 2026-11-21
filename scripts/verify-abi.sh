#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/abi.log") 2>&1

mkdir -p "$ARTIFACTS/elf-reports"
[[ -s "$ARTIFACTS/ota-rootfs-provenance.txt" ]] || {
  echo 'ERROR: checksum-verified OTA preparation provenance is missing; run prepare-capsule-rootfs.sh first.' >&2
  exit 1
}
for version in 15 14; do
  [[ -d "$WORK/ota/capsule$version/rootfs" ]] || {
    echo "ERROR: prepared Capsule-$version rootfs is missing." >&2
    exit 1
  }
done

failed=0
ancillary_failed=0
if readelf -h "$ARTIFACTS/libtensorflowlite_c.so" > "$ARTIFACTS/elf-reports/library-header.txt"; then
  if ! grep -q 'Class:.*ELF64' "$ARTIFACTS/elf-reports/library-header.txt"; then
    echo 'ERROR: ancillary ELF header report does not show ELF64.' >&2
    ancillary_failed=1
  fi
  if ! grep -q 'Machine:.*AArch64' "$ARTIFACTS/elf-reports/library-header.txt"; then
    echo 'ERROR: ancillary ELF header report does not show AArch64.' >&2
    ancillary_failed=1
  fi
else
  rc=$?
  echo "ERROR: ancillary readelf -h failed (exit=$rc); continuing with both strict OTA audits." >&2
  ancillary_failed=1
fi

for version in 15 14; do
  root="$WORK/ota/capsule$version/rootfs"
  report="$ARTIFACTS/elf-reports/capsule$version-abi.txt"
  echo "=== Strict ABI audit: Capsule-$version OTA 44.90 ==="
  if python3 "$ROOT/scripts/verify_elf_abi.py" "$ARTIFACTS/libtensorflowlite_c.so" "$root" 2>&1 | tee "$report"; then
    echo "Capsule-$version library ABI audit: PASS"
  else
    echo "Capsule-$version library ABI audit: FAIL" >&2
    failed=1
  fi
  if readelf -d "$ARTIFACTS/libtensorflowlite_c.so" > "$ARTIFACTS/elf-reports/capsule$version-dynamic.txt"; then
    :
  else
    rc=$?
    echo "ERROR: Capsule-$version ancillary readelf -d failed (exit=$rc); continuing to next OTA audit." >&2
    ancillary_failed=1
  fi
  if readelf --version-info -W "$ARTIFACTS/libtensorflowlite_c.so" > "$ARTIFACTS/elf-reports/capsule$version-versions.txt"; then
    :
  else
    rc=$?
    echo "ERROR: Capsule-$version ancillary readelf --version-info failed (exit=$rc); continuing to next OTA audit." >&2
    ancillary_failed=1
  fi
done
(( failed == 0 )) || exit 1
(( ancillary_failed == 0 )) || exit 1
