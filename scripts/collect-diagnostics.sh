#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/diagnostics.log") 2>&1

diagnostic_status=0
tf="$WORK/tensorflow"
bazel="$WORK/bin/bazelisk"
mkdir -p "$ARTIFACTS/elf-reports"
private_diagnostics="$WORK/private-diagnostics"
mkdir -p "$private_diagnostics"
chmod 700 "$private_diagnostics"

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

# Raw aquery command/environment output stays in the runner workspace. Never
# print it into the public Actions log; it may contain arbitrary action env data.
attempt_private_file_command() {
  local label="$1" output="$2"
  shift 2
  printf '\n=== %s ===\n' "$label"
  : > "$output"
  if "$@" > "$output" 2>&1; then
    if [[ -s "$output" ]]; then
      printf 'STATUS: private diagnostic output written (%s bytes).\n' "$(wc -c < "$output")"
    else
      printf 'ERROR: command succeeded but produced an empty private output for %s.\n' "$label" >&2
      fail_diagnostic "$label produced no output"
    fi
  else
    local rc=$?
    printf 'ERROR: command failed (exit=%s); raw output retained only on runner for %s.\n' "$rc" "$label" >&2
    fail_diagnostic "$label (exit=$rc)"
  fi
}

[[ -x "$bazel" ]] || fail_diagnostic 'Bazelisk executable is missing from the private runner workspace'
[[ -d "$tf/.git" ]] || fail_diagnostic 'pinned TensorFlow workspace is missing from the private runner workspace'
[[ -s "$ARTIFACTS/libtensorflowlite_c.so" ]] || fail_diagnostic 'built library is missing or empty'
[[ -s "$ARTIFACTS/tflite_smoke" ]] || fail_diagnostic 'smoke executable is missing or empty'

output_base=''
if [[ -x "$bazel" && -d "$tf" ]]; then
  info_output_file="$private_diagnostics/bazel-info-output-base.txt"
  if (cd "$tf" && USE_BAZEL_VERSION="$BAZEL_VERSION" "$bazel" \
      --output_user_root="$WORK/bazel-root" info output_base) > "$info_output_file" 2> "$private_diagnostics/bazel-info-stderr.txt"; then
    info_output="$(cat "$info_output_file")"
    output_base="${info_output##*$'\n'}"
    [[ -n "$output_base" ]] || fail_diagnostic 'Bazel info output_base returned an empty value'
  else
    rc=$?
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

config_report="$private_diagnostics/tensorflow-toolchain-config.txt"
: > "$config_report"
if [[ -d "$tf" ]]; then
  attempt_private_file_command 'TensorFlow pinned toolchain configuration excerpt' "$config_report" \
    bash -c 'cd "$1" && grep -n -A5 -B2 -E "elinux_aarch64|local_config_embedded_arm|aarch64_linux_toolchain" .bazelrc tensorflow/workspace2.bzl' \
    _ "$tf"
else
  printf 'ERROR: TensorFlow workspace unavailable: %s\n' "$tf" > "$config_report"
  fail_diagnostic 'cannot inspect pinned TensorFlow toolchain configuration'
fi

resolved_toolchain="$private_diagnostics/resolved-bazel-toolchain.txt"
if [[ -x "$bazel" && -d "$tf" ]]; then
  attempt_private_file_command 'Resolved generated Bazel toolchain target' "$resolved_toolchain" \
    bash -c 'cd "$1" && USE_BAZEL_VERSION="$2" "$3" --output_user_root="$4" query "@local_config_embedded_arm//:toolchain" --output=build' \
    _ "$tf" "$BAZEL_VERSION" "$bazel" "$WORK/bazel-root"
else
  printf 'ERROR: Bazel or TensorFlow workspace unavailable; toolchain target unresolved.\n' > "$resolved_toolchain"
  fail_diagnostic 'could not query the generated Bazel toolchain target'
fi

# The two JSONPROTO queries and collectors are deliberately isolated. A failure
# for one target must not prevent diagnostics for the other. Raw JSON and stderr
# are runner-private and never printed or added to artifacts.
for name in library smoke; do
  if [[ "$name" == library ]]; then
    target='//tensorflow/lite/c:libtensorflowlite_c.so'
  else
    target='//tensorflow/lite/c/cloud_smoke:tflite_smoke'
  fi
  actions="$private_diagnostics/actions-$name.json"
  action_stderr="$private_diagnostics/actions-$name.stderr"
  report="$private_diagnostics/toolchain-$name.txt"
  public_report="$ARTIFACTS/toolchain-$name-sanitized.txt"
  if [[ -x "$bazel" && -d "$tf" ]]; then
    expression="mnemonic(\"CppCompile|CppLink\", deps($target))"
    printf '\n=== Bazel JSONPROTO dependency-closure query for %s ===\n' "$name"
    : > "$actions"
    : > "$action_stderr"
    if (cd "$tf" && USE_BAZEL_VERSION="$BAZEL_VERSION" "$bazel" \
        --output_user_root="$WORK/bazel-root" aquery --config=elinux_aarch64 -c opt --jobs=2 \
        --output=jsonproto --include_param_files "$expression") > "$actions" 2> "$action_stderr"; then
      if [[ -s "$actions" ]]; then
        printf 'STATUS: private JSONPROTO captured for %s (%s bytes); stderr retained privately.\n' "$name" "$(wc -c < "$actions")"
      else
        printf 'ERROR: aquery succeeded but JSONPROTO output is empty for %s.\n' "$name" >&2
        fail_diagnostic "$name JSONPROTO query produced no output"
      fi
    else
      rc=$?
      printf 'ERROR: aquery failed for %s (exit=%s); JSON and stderr remain runner-private.\n' "$name" "$rc" >&2
      fail_diagnostic "$name JSONPROTO query (exit=$rc)"
    fi
  else
    printf 'ERROR: Bazel or TensorFlow workspace unavailable; actions unresolved.\n' > "$action_stderr"
    fail_diagnostic "cannot run $name Bazel action query"
  fi

  if [[ -z "$output_base" ]]; then
    collector_output_base='/__UNRESOLVED_BAZEL_OUTPUT_BASE__'
  else
    collector_output_base="$output_base"
  fi
  if [[ ! -s "$actions" ]]; then
    printf 'ERROR: action query output is missing or empty.\n' > "$report"
    fail_diagnostic "$name action report is missing or empty"
  fi
  : > "$report"
  attempt_command "Bazel toolchain collector for $name" \
    python3 "$ROOT/scripts/collect-bazel-toolchain.py" "$actions" "$tf" "$collector_output_base" "$report" "$name"
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
    abi_console="$private_diagnostics/abi-capsule$version-$name-console.txt"
    attempt_private_file_command "ABI diagnostic report for Capsule-$version $name" "$abi_console" "${args[@]}"
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
