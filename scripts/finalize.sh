#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
names=(preflight build abi smoke-build qemu)
values=("${1:-skipped}" "${2:-skipped}" "${3:-skipped}" "${4:-skipped}" "${5:-skipped}")
{
  echo 'TensorFlow Lite ARM64 cloud build result'
  echo 'Outputs are build artifacts; QEMU results do not certify execution on Capsule hardware.'
  for i in "${!names[@]}"; do printf '%s: %s\n' "${names[$i]}" "${values[$i]}"; done
} > "$ARTIFACTS/README.txt"
(cd "$ARTIFACTS" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 -r sha256sum > SHA256SUMS)
cat "$ARTIFACTS/README.txt"
for outcome in "${values[@]}"; do [[ "$outcome" == success ]] || exit 1; done
