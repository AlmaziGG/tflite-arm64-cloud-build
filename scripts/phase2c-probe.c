#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/auxv.h>
#include "tensorflow/lite/c/c_api.h"

int main(int argc, char **argv) {
    printf("caps=%lx,%lx\n", getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    if (argc == 1) return 0;
    Dl_info info;
    if (!dladdr(dlsym(RTLD_DEFAULT, "TfLiteInterpreterInvoke"), &info)) return 1;
    printf("base=%" PRIxPTR "\n", (uintptr_t)info.dli_fbase);
    TfLiteModel *model = TfLiteModelCreateFromFile(argv[1]);
    if (!model) return 2;
    TfLiteInterpreter *it = TfLiteInterpreterCreate(model, NULL);
    int rc = 3;
    if (!it || TfLiteInterpreterAllocateTensors(it) != kTfLiteOk ||
        TfLiteInterpreterGetInputTensorCount(it) != 1 || TfLiteInterpreterGetOutputTensorCount(it) != 1) goto done;
    TfLiteTensor *in = TfLiteInterpreterGetInputTensor(it, 0);
    if (!in || TfLiteTensorType(in) != kTfLiteInt8 || TfLiteTensorNumDims(in) != 3 ||
        TfLiteTensorDim(in,0)!=1 || TfLiteTensorDim(in,1)!=3 || TfLiteTensorDim(in,2)!=40 ||
        TfLiteTensorByteSize(in)!=120) goto done;
    uint32_t seed = 12345;
    int zp = TfLiteTensorQuantizationParams(in).zero_point;
    if (zp < -128 || zp > 127) goto done;
    printf("zp=%d\n", zp);
    for (int round=0; round<2; ++round) for (int k=0; k<6; ++k) {
        int8_t input[120];
        for (size_t i=0; i<sizeof(input); ++i) {
            seed = seed*1664525u + 1013904223u;
            const int values[] = {0, zp, 32, -32, i%2 ? 64 : -64, (int)(seed>>24)-128};
            input[i]=(int8_t)values[k];
        }
        if (TfLiteTensorCopyFromBuffer(in,input,sizeof(input)) != kTfLiteOk ||
            TfLiteInterpreterInvoke(it) != kTfLiteOk) goto done;
        const TfLiteTensor *out=TfLiteInterpreterGetOutputTensor(it,0);
        uint8_t value;
        if (!out || TfLiteTensorType(out)!=kTfLiteUInt8 || TfLiteTensorNumDims(out)!=2 ||
            TfLiteTensorDim(out,0)!=1 || TfLiteTensorDim(out,1)!=1 || TfLiteTensorByteSize(out)!=1 ||
            TfLiteTensorCopyToBuffer(out,&value,1)!=kTfLiteOk) goto done;
        printf("result=%d,%d,%u\n",round,k,(unsigned)value);
    }
    rc=0;
done:
    if (it) TfLiteInterpreterDelete(it);
    TfLiteModelDelete(model);
    return rc;
}
