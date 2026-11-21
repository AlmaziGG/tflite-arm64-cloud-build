#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/preflight.log") 2>&1
log 'Checking GitHub-hosted runner resources before downloads/build.'
printf 'runner=%s\n' "${ImageOS:-unknown}/${ImageVersion:-unknown}"
printf 'machine=%s\n' "$(uname -m)"
printf 'cpu_count=%s\n' "$(nproc)"
df -Pk "$WORK"
awk '/MemAvailable:/ {printf "mem_available_kib=%s\n", $2; printf "mem_available_gib=%.2f\n", $2/1024/1024}' /proc/meminfo
[[ "$(uname -m)" == 'x86_64' ]] || { echo 'Expected x86_64 build host.' >&2; exit 1; }
cpus="$(nproc)"
avail_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
free_kib="$(df -Pk "$WORK" | awk 'NR==2 {print $4}')"
(( cpus >= 4 )) || { echo "Insufficient CPU cores: $cpus (need >=4)." >&2; exit 1; }
(( avail_kib >= 8*1024*1024 )) || { echo "Insufficient MemAvailable: ${avail_kib} KiB (need >=8 GiB)." >&2; exit 1; }
(( free_kib >= 10*1024*1024 )) || { echo "Insufficient free disk: ${free_kib} KiB (need >=10 GiB)." >&2; exit 1; }
log 'Running ABI auditor regression tests.'
python3 "$ROOT/scripts/test_verify_elf_abi.py"
log 'Checking Python syntax for toolchain diagnostics.'
PYTHONPYCACHEPREFIX="$WORK/python-bytecode-cache" python3 -m py_compile \
  "$ROOT/scripts/collect-bazel-toolchain.py" \
  "$ROOT/scripts/sanitize-toolchain-report.py" \
  "$ROOT/scripts/test_collect_bazel_toolchain.py"
log 'Running Bazel toolchain diagnostics regression tests.'
python3 "$ROOT/scripts/test_collect_bazel_toolchain.py"
log 'Preflight passed. Thresholds are conservative guards, not TensorFlow minimum requirements.'
