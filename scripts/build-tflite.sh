#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/build.log") 2>&1
sudo apt-get update
sudo apt-get install -y --no-install-recommends curl ca-certificates git python3 unzip file binutils dpkg-dev
cd "$WORK"
if [[ ! -d tensorflow/.git ]]; then
  git clone --filter=blob:none --no-checkout https://github.com/tensorflow/tensorflow.git tensorflow
fi
cd tensorflow
git fetch --depth=1 origin "refs/tags/$TF_TAG:refs/tags/$TF_TAG"
resolved="$(git rev-parse "$TF_TAG^{commit}")"
[[ "$resolved" == "$TF_COMMIT" ]] || { echo "TensorFlow tag resolved to $resolved, expected $TF_COMMIT" >&2; exit 1; }
git checkout --detach "$TF_COMMIT"
if [[ "${CAPSULE_ARMGNU103:-0}" == 1 ]]; then
  python3 "$ROOT/scripts/phase2b.py" configure "$PWD"
fi
raw_bazel_version="$(cat .bazelversion)"
actual_bazel="$(printf '%s\n' "$raw_bazel_version" | awk '
  {
    sub(/\r$/, "")
    sub(/#.*/, "")
    for (i = 1; i <= NF; i++) {
      print $i
      exit
    }
  }
')"
if [[ "$actual_bazel" != "$BAZEL_VERSION" ]]; then
  printf 'ERROR: .bazelversion does not match the required Bazel version.\nExpected: %s\nRecognized: %s\nOriginal contents:\n%s\n' \
    "$BAZEL_VERSION" "${actual_bazel:-<empty>}" "$raw_bazel_version" >&2
  exit 1
fi
mkdir -p "$WORK/bin"
curl --fail --location --retry 3 "https://github.com/bazelbuild/bazelisk/releases/download/$BAZELISK_VERSION/bazelisk-amd64.deb" -o "$WORK/bazelisk-amd64.deb"
[[ "$(sha256sum "$WORK/bazelisk-amd64.deb" | awk '{print $1}')" == "$BAZELISK_SHA256" ]] || { echo 'Bazelisk package SHA-256 mismatch.' >&2; exit 1; }
dpkg-deb -x "$WORK/bazelisk-amd64.deb" "$WORK/bazelisk-package"
install -m 0755 "$WORK/bazelisk-package/usr/bin/bazelisk" "$WORK/bin/bazelisk"
USE_BAZEL_VERSION="$BAZEL_VERSION" "$WORK/bin/bazelisk" --output_user_root="$WORK/bazel-root" build \
  --config=elinux_aarch64 -c opt --jobs=2 \
  --repository_cache="$WORK/repository-cache" \
  //tensorflow/lite/c:libtensorflowlite_c.so
lib='bazel-bin/tensorflow/lite/c/libtensorflowlite_c.so'
if [[ ! -s "$lib" ]]; then
  echo "ERROR: expected non-empty Bazel output at $lib" >&2
  echo 'Bazel output diagnostics:' >&2
  ls -ld bazel-bin bazel-out bazel-testlogs 2>&1 || true
  ls -la bazel-bin/ 2>&1 || true
  find -L bazel-bin -maxdepth 6 -type f -name 'libtensorflowlite_c.so' -printf '%p (%s bytes)\n' 2>&1 || true
  exit 1
fi
install -m 0644 "$lib" "$ARTIFACTS/libtensorflowlite_c.so"
readelf -h "$ARTIFACTS/libtensorflowlite_c.so" | tee "$ARTIFACTS/elf-header.txt"
file "$ARTIFACTS/libtensorflowlite_c.so" | tee "$ARTIFACTS/elf-file.txt"
