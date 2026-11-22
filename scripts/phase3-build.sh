#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/common.sh"
mkdir -p work/p3
fetch() {
  local name=$1 repo=$2 commit=$3 digest=$4
  curl -fsSL --retry 3 "https://codeload.github.com/$repo/tar.gz/$commit" -o "work/p3/$name.tgz"
  require_sha256 "work/p3/$name.tgz" "$digest"
  mkdir -p "work/p3/$name"
  tar -xzf "work/p3/$name.tgz" --strip-components=1 -C "work/p3/$name"
}
fetch dsp kahrendt/ESPMicroSpeechFeatures de34b9feaa99301cea3cef4e13a2c2bbe6749e94 a41383948d9c839cf1106d1e18320267113397a65772b02014a00ad057132d57
fetch esp esphome/esphome 7c9726859f957e26f718abae49ace3fcd9f93b26 42201fea1f9db04ba18189fb89b0be6ac4252d046466541b3133aaf0758b438d
fetch rust akash-kamat/microwakeword-rs cf7006dccd3db4e04b85ff87cf38e15ab3ea329e 317932eb28a977e5c336063bf1c157b8c7c20de2910f15dd86fc78b928cb42fb
curl -fsSL --retry 3 "$MODEL_URL" -o work/model
require_sha256 work/model "$MODEL_SHA256"
curl -fsSL --retry 3 "${MODEL_URL%.tflite}.json" -o work/model.json
for h in c/c_api.h core/c/c_api.h builtin_ops.h core/async/c/types.h core/c/c_api_types.h core/c/operator.h; do
  dest="work/include/tensorflow/lite/$h"
  mkdir -p "$(dirname "$dest")"
  curl -fsSL --retry 3 "https://raw.githubusercontent.com/tensorflow/tensorflow/$TF_COMMIT/tensorflow/lite/$h" -o "$dest"
done
python3 scripts/phase3-oracle.py
d=work/p3/dsp
gcc -std=gnu11 -O2 -I"$d/include" -I"$d/src" work/p3/oracle.c "$d"/src/*.c -lm -o work/p3/oracle
v=work/p3/rust/native/vendor
src="$v/tensorflow/lite/experimental/microfrontend/lib"
units=(kiss_fft_int16 fft fft_util filterbank filterbank_util frontend frontend_util log_lut log_scale log_scale_util noise_reduction noise_reduction_util pcan_gain_control pcan_gain_control_util window window_util)
sources=(work/p3/rust/native/frontend_bridge.cc "$v/kissfft/kiss_fft.cc" "$v/kissfft/tools/kiss_fftr.cc")
for u in "${units[@]}"; do sources+=("$src/$u.cc"); done
flags=(-O2 -std=c++17 -DFIXED_POINT=16 -I"$v" -I"$v/kissfft")
g++ "${flags[@]}" -DFEATURES_ONLY scripts/phase3-runner.cc "${sources[@]}" -o work/p3/host
python3 scripts/phase3.py golden
cc=work/armgnu103/bin/aarch64-none-linux-gnu
strace -f -e execve -o work/p3/compiler.trace "$cc-g++" -march=armv8-a "${flags[@]}" -Iwork/include scripts/phase3-runner.cc "${sources[@]}" -Lartifacts -ltensorflowlite_c -Wl,-t -o work/p3/runner > work/p3/link.inputs
grep -Eq 'execve\("[^"]*/ld[^"]*".*= 0$' work/p3/compiler.trace
grep -F 'artifacts/libtensorflowlite_c.so' work/p3/link.inputs
"$cc-gcc" -std=c11 -O2 -march=armv8-a -Iwork/include scripts/phase3-replay.c -Lartifacts -ltensorflowlite_c -o work/p3/replay
