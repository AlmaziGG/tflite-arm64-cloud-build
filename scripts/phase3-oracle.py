"""Build a private host oracle from the pinned ESPHome expressions and its own C DSP."""
import re
from pathlib import Path

p = Path("work/p3")
source = (p / "esp/esphome/components/micro_wake_word/micro_wake_word.cpp").read_text()
settings = re.findall(r"this->frontend_config_\.([\w.]+) = ([^;]+);", source)
if len(settings) != 15:
    raise ValueError("unexpected reference configuration")
constants = {"FEATURE_DURATION_MS": "30", "this->features_step_size_": "10", "PREPROCESSOR_FEATURE_SIZE": "40"}
config = "\n".join(f"cfg.{key} = {constants.get(value, value)};" for key, value in settings)
start = source.index("constexpr int32_t value_scale")
end = source.index("features[i] = value;", start) + len("features[i] = value;")
quant = source[start:end].replace("constexpr", "const")
(p / "oracle.c").write_text("""
#include <stdint.h>
#include <stdio.h>
#include "frontend_util.h"
int main(void) {
    struct FrontendConfig cfg = {0};
    struct FrontendState state = {0};
""" + config + """
    if (!FrontendPopulateState(&cfg, &state, 16000)) return 2;
    int16_t samples[160];
    while (fread(samples, sizeof *samples, 160, stdin) == 160) {
        size_t used = 0;
        struct FrontendOutput frontend_output = FrontendProcessSamples(&state, samples, 160, &used);
        if (used != 160) return 3;
        if (!frontend_output.size) continue;
        if (frontend_output.size != 40) return 4;
        int8_t features[40];
        for (size_t i = 0; i < 40; ++i) {
""" + quant + """
        }
        if (fwrite(frontend_output.values, 2, 40, stdout) != 40 ||
            fwrite(features, 1, 40, stdout) != 40) return 5;
    }
    FrontendFreeStateContents(&state);
    return ferror(stdin) || fflush(stdout);
}
""")
