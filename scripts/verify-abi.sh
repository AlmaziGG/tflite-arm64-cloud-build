#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
exec > >(tee "$ARTIFACTS/abi.log") 2>&1
sudo apt-get update
sudo apt-get install -y --no-install-recommends curl ca-certificates git cargo rustc squashfs-tools binutils python3
mkdir -p "$WORK/ota" "$ARTIFACTS/elf-reports"
for spec in "15|$CAPSULE15_URL|$CAPSULE15_SHA256" "14|$CAPSULE14_URL|$CAPSULE14_SHA256"; do
  IFS='|' read -r version url expected <<< "$spec"
  ota="$WORK/ota/Capsule-$version-44.90.ota"
  [[ -s "$ota" ]] || curl --fail --location --retry 3 "$url" -o "$ota"
  require_sha256 "$ota" "$expected"
done
if [[ ! -d "$WORK/afptool-rs/.git" ]]; then
  git init "$WORK/afptool-rs"
  git -C "$WORK/afptool-rs" remote add origin "$AFPTOOL_REPO"
fi
git -C "$WORK/afptool-rs" fetch --depth=1 origin "$AFPTOOL_COMMIT"
git -C "$WORK/afptool-rs" checkout --detach FETCH_HEAD
[[ "$(git -C "$WORK/afptool-rs" rev-parse HEAD)" == "$AFPTOOL_COMMIT" ]]
cargo build --release --locked --manifest-path "$WORK/afptool-rs/Cargo.toml"
AFPTOOL="$WORK/afptool-rs/target/release/afptool-rs"
readelf -h "$ARTIFACTS/libtensorflowlite_c.so" > "$ARTIFACTS/elf-reports/library-header.txt"
grep -q 'Class:.*ELF64' "$ARTIFACTS/elf-reports/library-header.txt"
grep -q 'Machine:.*AArch64' "$ARTIFACTS/elf-reports/library-header.txt"
for version in 15 14; do
  stage="$WORK/ota/capsule$version"
  mkdir -p "$stage/rkfw" "$stage/rkaf" "$stage/rootfs"
  "$AFPTOOL" unpack "$WORK/ota/Capsule-$version-44.90.ota" "$stage/rkfw"
  "$AFPTOOL" unpack "$stage/rkfw/embedded-update.img" "$stage/rkaf"
  metadata="$stage/rkaf/partition-metadata.txt"
  if [[ ! -s "$metadata" ]]; then
    echo "ERROR: afptool-rs did not create non-empty RKAF metadata: $metadata" >&2
    find "$stage/rkaf" -type f -printf '%p (%s bytes)\n' 2>&1 | sort >&2 || true
    exit 1
  fi
  mapfile -t rootfs_metadata_paths < <(awk -F, 'index($0, "rootfs_dmv.img") { print $2 }' "$metadata")
  if (( ${#rootfs_metadata_paths[@]} != 1 )); then
    echo "ERROR: expected one RKAF metadata row for rootfs_dmv.img; found ${#rootfs_metadata_paths[@]}" >&2
    cat "$metadata" >&2
    exit 1
  fi
  echo "Capsule-$version RKAF metadata row:"
  grep -F 'rootfs_dmv.img' "$metadata"
  metadata_relpath="${rootfs_metadata_paths[0]#/}"
  metadata_image="$(realpath -e "$stage/rkaf/$metadata_relpath" 2>/dev/null || true)"
  case "$metadata_image" in
    "$stage/rkaf"/*) ;;
    *) echo "ERROR: metadata rootfs path is missing or escapes the RKAF output directory: ${rootfs_metadata_paths[0]}" >&2; exit 1 ;;
  esac
  [[ -s "$metadata_image" ]] || { echo "ERROR: metadata rootfs image is empty: $metadata_image" >&2; exit 1; }
  mapfile -t rootfs_images < <(find "$stage/rkaf" -type f -name rootfs_dmv.img -size +0c -print)
  if (( ${#rootfs_images[@]} != 1 )); then
    echo "ERROR: expected exactly one non-empty rootfs_dmv.img under $stage/rkaf; found ${#rootfs_images[@]}" >&2
    echo 'Extracted files (path and byte size):' >&2
    find "$stage/rkaf" -type f -printf '%p (%s bytes)\n' 2>&1 | sort >&2 || true
    exit 1
  fi
  rootfs_image="${rootfs_images[0]}"
  [[ "$(realpath -e "$rootfs_image")" == "$metadata_image" ]] || {
    echo "ERROR: recursively found rootfs does not match the partition-metadata full_path." >&2
    echo "metadata=$metadata_image discovered=$rootfs_image" >&2
    exit 1
  }
  echo "Capsule-$version RKAF rootfs: $rootfs_image ($(stat -c '%s bytes' "$rootfs_image"))"
  unsquashfs -no-progress -d "$stage/rootfs" "$rootfs_image"
  python3 "$ROOT/scripts/verify_elf_abi.py" "$ARTIFACTS/libtensorflowlite_c.so" "$stage/rootfs" \
    | tee "$ARTIFACTS/elf-reports/capsule$version-abi.txt"
  readelf -d "$ARTIFACTS/libtensorflowlite_c.so" > "$ARTIFACTS/elf-reports/capsule$version-dynamic.txt"
  readelf --version-info "$ARTIFACTS/libtensorflowlite_c.so" > "$ARTIFACTS/elf-reports/capsule$version-versions.txt"
done
