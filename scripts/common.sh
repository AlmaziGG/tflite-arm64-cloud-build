#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$ROOT/work"
ARTIFACTS="$ROOT/artifacts"
TF_TAG='v2.17.1'
TF_COMMIT='3c92ac03cab816044f7b18a86eb86aa01a294d95'
BAZEL_VERSION='6.5.0'
BAZELISK_VERSION='v1.29.0'
BAZELISK_SHA256='186d78a20e1a64f59ba08987791a989892d142c9d3a9f9cc0c5c35e201f53924'
MODEL_URL='https://raw.githubusercontent.com/olegchumakov/microwakeword-models/7a3490e3c5de3ec21442abcc7a44c74fd979917a/alisa/alisa_mww.tflite'
MODEL_SHA256='481cf6c180d3b5cbebfa6af47b4f9544c631d05b73cecf51fb8363ab7d143f38'
CAPSULE15_URL='https://vcfw.vkcdn.ru/Capsule-15/44.90'
CAPSULE15_SHA256='AA219C810CFE5C0AC9D761832962FF33236E484A377B5076EE3CB1E56347FDE4'
CAPSULE14_URL='https://vcfw.vkcdn.ru/Capsule-14/44.90'
CAPSULE14_SHA256='B13AF88714CFC114F2C6909C6E56A2ECBEFC77D4FB857DF0E78BACFF0A44AD26'
AFPTOOL_REPO='https://github.com/suyulin/afptool-rs.git'
AFPTOOL_COMMIT='501d4a1d4d6c6800bdfb42b3a97761a804fd93df'
mkdir -p "$WORK" "$ARTIFACTS"
log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
sha256_file() { sha256sum "$1" | awk '{print toupper($1)}'; }
require_sha256() {
  local file="$1" expected="${2^^}" actual
  actual="$(sha256_file "$file")"
  [[ "$actual" == "$expected" ]] || { echo "SHA-256 mismatch for $file: $actual != $expected" >&2; return 1; }
}
