#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
names=(preflight ota-rootfs build smoke-build diagnostics library-abi smoke-abi qemu)
values=("${1:-skipped}" "${2:-skipped}" "${3:-skipped}" "${4:-skipped}" "${5:-skipped}" "${6:-skipped}" "${7:-skipped}" "${8:-skipped}")
{
  echo 'TensorFlow Lite ARM64 cloud build result'
  echo 'Outputs are build artifacts; QEMU results do not certify execution on Capsule hardware.'
  for i in "${!names[@]}"; do printf '%s: %s\n' "${names[$i]}" "${values[$i]}"; done
} > "$ARTIFACTS/README.txt"
if [[ "${values[4]}" != success ]]; then
  printf 'WARNING: diagnostic collection status: %s. Diagnostics are informational and are not an acceptance gate.\n' \
    "${values[4]}" | tee -a "$ARTIFACTS/README.txt"
fi
(
  cd "$ARTIFACTS"
  shopt -s nullglob
  manifest_files=(
    libtensorflowlite_c.so tflite_smoke elf-header.txt elf-file.txt
    elf-reports/*.txt preflight.log ota-prepare.log ota-rootfs-provenance.txt
    build.log abi.log smoke-build.log smoke-abi.log diagnostics.log
    toolchain-context.txt tensorflow-toolchain-config.txt resolved-bazel-toolchain.txt
    toolchain-library-sanitized.txt toolchain-smoke-sanitized.txt qemu.log README.txt
  )
  for file in "${manifest_files[@]}"; do
    [[ -f "$file" ]] && sha256sum "$file"
  done
) > "$ARTIFACTS/SHA256SUMS"
cat "$ARTIFACTS/README.txt"
required_indices=(0 1 2 3 5 6 7)
for index in "${required_indices[@]}"; do
  [[ "${values[$index]}" == success ]] || exit 1
done
