/* Reference path: feed host-oracle features directly to the immutable guest library. */
#include <stdint.h>
#include <stdio.h>
#include "tensorflow/lite/c/c_api.h"
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    TfLiteModel *m = TfLiteModelCreateFromFile(argv[1]);
    if (!m) return 2;
    TfLiteInterpreterOptions *opts = TfLiteInterpreterOptionsCreate();
    if (!opts) return 3;
    TfLiteInterpreterOptionsSetNumThreads(opts, 1);
    TfLiteInterpreter *it = TfLiteInterpreterCreate(m, opts);
    if (!it || TfLiteInterpreterAllocateTensors(it) != kTfLiteOk) return 4;
    int8_t input[120];
    size_t n;
    while ((n = fread(input, 1, sizeof input, stdin)) == sizeof input) {
        uint8_t raw;
        if (TfLiteTensorCopyFromBuffer(TfLiteInterpreterGetInputTensor(it, 0), input, n) != kTfLiteOk ||
            TfLiteInterpreterInvoke(it) != kTfLiteOk ||
            TfLiteTensorCopyToBuffer(TfLiteInterpreterGetOutputTensor(it, 0), &raw, 1) != kTfLiteOk ||
            putchar(raw) == EOF) return 5;
    }
    TfLiteInterpreterDelete(it);
    TfLiteInterpreterOptionsDelete(opts);
    TfLiteModelDelete(m);
    return n != 0 || ferror(stdin) || fflush(stdout);
}
