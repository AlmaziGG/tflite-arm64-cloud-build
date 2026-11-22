#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
# Isolated reproduction solely to recover the private link map. The model
# continues to run with the previously downloaded reference library.
lab="$WORK/isa-symbols"
mkdir -p "$lab/work"
cp -r scripts "$lab/"
cp -al "$WORK/armgnu103" "$lab/work/armgnu103"
export CAPSULE_ARMGNU103=1
bash "$lab/scripts/build-tflite.sh"
cmp "$lab/artifacts/libtensorflowlite_c.so" "$ARTIFACTS/libtensorflowlite_c.so"
cd "$lab/work/tensorflow"
bazel=("$lab/work/bin/bazelisk" "--output_user_root=$lab/work/bazel-root")
export USE_BAZEL_VERSION="$BAZEL_VERSION"
"${bazel[@]}" aquery --config=elinux_aarch64 -c opt --output=jsonproto --include_param_files 'mnemonic("Cpp(Compile|Link)",deps(//tensorflow/lite/c:libtensorflowlite_c.so))' > "$lab/actions.json"
"${bazel[@]}" info execution_root > "$lab/execroot"
cd "$ROOT"
python3 scripts/phase2c-symbols.py
