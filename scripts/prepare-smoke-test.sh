#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/smoke-build.log") 2>&1
sudo apt-get update
sudo apt-get install -y --no-install-recommends curl ca-certificates qemu-user
model="$WORK/alisa_mww.tflite"
curl --fail --location --retry 3 "$MODEL_URL" -o "$model"
require_sha256 "$model" "$MODEL_SHA256"

tf="$WORK/tensorflow"
pkg="$tf/tensorflow/lite/c/cloud_smoke"
mkdir -p "$pkg"
cp "$ROOT/scripts/tflite_smoke.c" "$pkg/tflite_smoke.c"
cp "$ARTIFACTS/libtensorflowlite_c.so" "$pkg/libtensorflowlite_c.so"
mkdir -p "$pkg/include/tensorflow/lite/c" "$pkg/include/tensorflow/lite/core/c" "$pkg/include/tensorflow/lite/core/async/c"
find "$tf/tensorflow/lite/c" -maxdepth 1 -type f -name '*.h' -exec cp '{}' "$pkg/include/tensorflow/lite/c/" \;
find "$tf/tensorflow/lite/core/c" -maxdepth 1 -type f -name '*.h' -exec cp '{}' "$pkg/include/tensorflow/lite/core/c/" \;
cp "$tf/tensorflow/lite/builtin_ops.h" "$pkg/include/tensorflow/lite/builtin_ops.h"
cp "$tf/tensorflow/lite/core/async/c/types.h" "$pkg/include/tensorflow/lite/core/async/c/types.h"
for header in \
  "$pkg/include/tensorflow/lite/c/c_api.h" \
  "$pkg/include/tensorflow/lite/core/c/c_api.h" \
  "$pkg/include/tensorflow/lite/core/c/c_api_types.h" \
  "$pkg/include/tensorflow/lite/core/c/operator.h" \
  "$pkg/include/tensorflow/lite/builtin_ops.h" \
  "$pkg/include/tensorflow/lite/core/async/c/types.h"; do
  [[ -s "$header" ]] || { echo "Required pinned TensorFlow C API header missing: $header" >&2; exit 1; }
done
cat > "$pkg/BUILD" <<'BUILD'
cc_import(
    name = "tflite_c_import",
    shared_library = "libtensorflowlite_c.so",
)

cc_library(
    name = "tflite_c_api_headers",
    hdrs = glob([
        "include/tensorflow/lite/c/*.h",
        "include/tensorflow/lite/core/c/*.h",
        "include/tensorflow/lite/core/async/c/*.h",
        "include/tensorflow/lite/builtin_ops.h",
    ]),
    includes = ["include"],
)

cc_binary(
    name = "tflite_smoke",
    srcs = ["tflite_smoke.c"],
    deps = [":tflite_c_api_headers", ":tflite_c_import"],
)
BUILD
cd "$tf"
USE_BAZEL_VERSION="$BAZEL_VERSION" "$WORK/bin/bazelisk" --output_user_root="$WORK/bazel-root" build \
  --config=elinux_aarch64 -c opt --jobs=2 //tensorflow/lite/c/cloud_smoke:tflite_smoke
smoke='bazel-bin/tensorflow/lite/c/cloud_smoke/tflite_smoke'
if [[ ! -s "$smoke" ]]; then
  echo "ERROR: expected non-empty Bazel output at $smoke" >&2
  echo 'Bazel output diagnostics:' >&2
  ls -ld bazel-bin bazel-out bazel-testlogs 2>&1 || true
  ls -la bazel-bin/tensorflow/lite/c/cloud_smoke/ 2>&1 || true
  find -L bazel-bin -maxdepth 8 -type f -name tflite_smoke -printf '%p (%s bytes)\n' 2>&1 || true
  exit 1
fi
install -m 0755 "$smoke" "$ARTIFACTS/tflite_smoke"
cp "$model" "$WORK/smoke-model.tflite"
for version in 15 14; do
  python3 "$ROOT/scripts/verify_elf_abi.py" "$ARTIFACTS/tflite_smoke" "$WORK/ota/capsule$version/rootfs" "$ARTIFACTS" \
    > "$ARTIFACTS/elf-reports/capsule$version-smoke-abi.txt"
done
qemu-aarch64 --version | head -n 1
readelf -h "$ARTIFACTS/tflite_smoke"
