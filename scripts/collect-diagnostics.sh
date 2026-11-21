#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/diagnostics.log") 2>&1

diagnostic_status=0
tf="$WORK/tensorflow"
bazel="$WORK/bin/bazelisk"
mkdir -p "$ARTIFACTS/elf-reports"
private_diagnostics="$WORK/private-diagnostics"
mkdir -p "$private_diagnostics"

fail_diagnostic() {
  printf 'DIAGNOSTIC FAILURE: %s\n' "$*" >&2
  diagnostic_status=1
}

attempt_command() {
  local label="$1"
  shift
  printf '\n=== %s ===\n' "$label"
  if "$@"; then
    printf 'STATUS: command completed: %s\n' "$label"
  else
    local rc=$?
    fail_diagnostic "$label (exit=$rc)"
  fi
}

attempt_file_command() {
  local label="$1" output="$2"
  shift 2
  printf '\n=== %s ===\n' "$label"
  : > "$output"
  if "$@" > "$output" 2>&1; then
    cat "$output"
    if [[ -s "$output" ]]; then
      printf 'STATUS: output written: %s\n' "$output"
    else
      printf 'ERROR: command succeeded but produced an empty output: %s\n' "$output" >&2
      fail_diagnostic "$label produced no output"
    fi
  else
    local rc=$?
    cat "$output"
    printf 'ERROR: command failed (exit=%s); output: %s\n' "$rc" "$output" >&2
    fail_diagnostic "$label (exit=$rc)"
  fi
}

# Raw aquery command/environment output stays in the runner workspace. Never
# print it into the public Actions log; it may contain arbitrary action env data.
attempt_private_file_command() {
  local label="$1" output="$2"
  shift 2
  printf '\n=== %s ===\n' "$label"
  : > "$output"
  if "$@" > "$output" 2>&1; then
    if [[ -s "$output" ]]; then
      printf 'STATUS: private diagnostic output written: %s\n' "$output"
    else
      printf 'ERROR: command succeeded but produced an empty private output: %s\n' "$output" >&2
      fail_diagnostic "$label produced no output"
    fi
  else
    local rc=$?
    printf 'ERROR: command failed (exit=%s); raw output retained only on runner: %s\n' "$rc" "$output" >&2
    fail_diagnostic "$label (exit=$rc)"
  fi
}

[[ -x "$bazel" ]] || fail_diagnostic "Bazelisk executable is missing: $bazel"
[[ -d "$tf/.git" ]] || fail_diagnostic "pinned TensorFlow workspace is missing: $tf"
[[ -s "$ARTIFACTS/libtensorflowlite_c.so" ]] || fail_diagnostic 'built library is missing or empty'
[[ -s "$ARTIFACTS/tflite_smoke" ]] || fail_diagnostic 'smoke executable is missing or empty'

output_base=''
if [[ -x "$bazel" && -d "$tf" ]]; then
  if info_output="$(cd "$tf" && USE_BAZEL_VERSION="$BAZEL_VERSION" "$bazel" \
      --output_user_root="$WORK/bazel-root" info output_base 2>&1)"; then
    output_base="${info_output##*$'\n'}"
    [[ -n "$output_base" ]] || fail_diagnostic 'Bazel info output_base returned an empty value'
  else
    rc=$?
    printf '%s\n' "$info_output" >&2
    fail_diagnostic "Bazel info output_base failed (exit=$rc)"
  fi
else
  fail_diagnostic 'cannot query Bazel output_base because Bazelisk or TensorFlow workspace is unavailable'
fi

{
  printf 'tensorflow_tag=%s\ntensorflow_commit=%s\nbazel_version=%s\n' "$TF_TAG" "$TF_COMMIT" "$BAZEL_VERSION"
  if [[ -n "$output_base" ]]; then
    printf 'output_base=%s\n' "$output_base"
  else
    printf 'output_base=<UNRESOLVED>\n'
  fi
} > "$ARTIFACTS/toolchain-context.txt"

config_report="$ARTIFACTS/tensorflow-toolchain-config.txt"
: > "$config_report"
if [[ -d "$tf" ]]; then
  attempt_file_command 'TensorFlow pinned toolchain configuration excerpt' "$config_report" \
    bash -c 'cd "$1" && grep -n -A5 -B2 -E "elinux_aarch64|local_config_embedded_arm|aarch64_linux_toolchain" .bazelrc tensorflow/workspace2.bzl' \
    _ "$tf"
else
  printf 'ERROR: TensorFlow workspace unavailable: %s\n' "$tf" > "$config_report"
  fail_diagnostic 'cannot inspect pinned TensorFlow toolchain configuration'
fi

resolved_toolchain="$ARTIFACTS/resolved-bazel-toolchain.txt"
if [[ -x "$bazel" && -d "$tf" ]]; then
  attempt_file_command 'Resolved generated Bazel toolchain target' "$resolved_toolchain" \
    bash -c 'cd "$1" && USE_BAZEL_VERSION="$2" "$3" --output_user_root="$4" query "@local_config_embedded_arm//:toolchain" --output=build' \
    _ "$tf" "$BAZEL_VERSION" "$bazel" "$WORK/bazel-root"
else
  printf 'ERROR: Bazel or TensorFlow workspace unavailable; toolchain target unresolved.\n' > "$resolved_toolchain"
  fail_diagnostic 'could not query the generated Bazel toolchain target'
fi

# The two action queries and the two toolchain collectors are deliberately
# isolated. A failure for one target must not prevent diagnostics for the other.
for target in '//tensorflow/lite/c:libtensorflowlite_c.so' '//tensorflow/lite/c/cloud_smoke:tflite_smoke'; do
  if [[ "$target" == *cloud_smoke* ]]; then name=smoke; else name=library; fi
  actions="$private_diagnostics/actions-$name.txt"
  report="$private_diagnostics/toolchain-$name.txt"
  public_report="$ARTIFACTS/toolchain-$name-sanitized.txt"
  if [[ -x "$bazel" && -d "$tf" ]]; then
    attempt_private_file_command "Bazel CppCompile/CppLink action query for $name" "$actions" \
      bash -c 'cd "$1" && USE_BAZEL_VERSION="$2" "$3" --output_user_root="$4" aquery --config=elinux_aarch64 --output=text --include_commandline "mnemonic(\"CppCompile|CppLink\", $5)"' \
      _ "$tf" "$BAZEL_VERSION" "$bazel" "$WORK/bazel-root" "$target"
  else
    printf 'ERROR: Bazel or TensorFlow workspace unavailable; actions unresolved.\n' > "$actions"
    fail_diagnostic "cannot run $name Bazel action query"
  fi

  if [[ -z "$output_base" ]]; then
    collector_output_base='/__UNRESOLVED_BAZEL_OUTPUT_BASE__'
  else
    collector_output_base="$output_base"
  fi
  if [[ ! -s "$actions" ]]; then
    printf 'ERROR: action query output is missing or empty.\n' > "$actions"
    fail_diagnostic "$name action report is missing or empty"
  fi
  : > "$report"
  attempt_command "Bazel toolchain collector for $name" \
    python3 "$ROOT/scripts/collect-bazel-toolchain.py" "$actions" "$tf" "$collector_output_base" "$report"
  if [[ ! -s "$report" ]]; then
    printf 'ERROR: toolchain collector did not produce this report.\n' > "$report"
    fail_diagnostic "$name toolchain diagnostic report is missing or empty"
  fi
  : > "$public_report"
  attempt_command "Sanitize public toolchain report for $name" \
    python3 "$ROOT/scripts/sanitize-toolchain-report.py" "$report" "$public_report"
  if [[ ! -s "$public_report" ]]; then
    printf 'Sanitization failed; see private runner diagnostics.\n' > "$public_report"
    fail_diagnostic "$name sanitized toolchain report is missing or empty"
  fi
done

# Attempt every target/rootfs pair even if an earlier report cannot be created.
for version in 15 14; do
  root="$WORK/ota/capsule$version/rootfs"
  for name in library smoke; do
    if [[ "$name" == library ]]; then
      target="$ARTIFACTS/libtensorflowlite_c.so"
      report="$ARTIFACTS/elf-reports/capsule$version-library-diagnostics.txt"
      args=(python3 "$ROOT/scripts/report-abi-diagnostics.py" "$target" "$root" "$report")
    else
      target="$ARTIFACTS/tflite_smoke"
      report="$ARTIFACTS/elf-reports/capsule$version-smoke-diagnostics.txt"
      args=(python3 "$ROOT/scripts/report-abi-diagnostics.py" "$target" "$root" "$report" \
        --allow-library "$ARTIFACTS/libtensorflowlite_c.so")
    fi
    : > "$report"
    attempt_command "ABI diagnostic report for Capsule-$version $name" "${args[@]}"
    if [[ ! -s "$report" ]]; then
      printf 'ERROR: ABI diagnostic generator did not produce this report.\n' > "$report"
      fail_diagnostic "Capsule-$version $name ABI diagnostic output is missing or empty"
    fi
  done
done

if (( diagnostic_status != 0 )); then
  echo 'Diagnostic collection completed with failures; see the per-operation status above.' >&2
  exit 1
fi
echo 'All requested diagnostic operations completed and produced non-empty reports.'
