#include <stdint.h>
#include <stdio.h>
#include "tensorflow/lite/c/c_api.h"

static int print_scalar(const TfLiteTensor *tensor) {
  if (!tensor) {
    fprintf(stderr, "output tensor is unavailable\n");
    return 0;
  }
  if (TfLiteTensorByteSize(tensor) == 0 || !TfLiteTensorData(tensor)) {
    fprintf(stderr, "output tensor has no readable data\n");
    return 0;
  }
  const void *data = TfLiteTensorData(tensor);
  switch (TfLiteTensorType(tensor)) {
    case kTfLiteFloat32:
      if (TfLiteTensorByteSize(tensor) < sizeof(float)) break;
      printf("output[0]=%g\n", (double)((const float *)data)[0]);
      return 1;
    case kTfLiteInt8:
      printf("output[0]=%d\n", (int)((const int8_t *)data)[0]);
      return 1;
    case kTfLiteUInt8:
      printf("output[0]=%u\n", (unsigned)((const uint8_t *)data)[0]);
      return 1;
    case kTfLiteInt32:
      if (TfLiteTensorByteSize(tensor) < sizeof(int32_t)) break;
      printf("output[0]=%d\n", ((const int32_t *)data)[0]);
      return 1;
    default:
      break;
  }
  fprintf(stderr, "output tensor is too small or has unsupported type %d\n",
          TfLiteTensorType(tensor));
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) { fprintf(stderr, "usage: %s model.tflite\n", argv[0]); return 2; }
  int result = 0;
  TfLiteModel *model = NULL;
  TfLiteInterpreterOptions *options = NULL;
  TfLiteInterpreter *interpreter = NULL;

  model = TfLiteModelCreateFromFile(argv[1]);
  if (!model) { fprintf(stderr, "TfLiteModelCreateFromFile failed\n"); result = 3; goto cleanup; }
  options = TfLiteInterpreterOptionsCreate();
  if (!options) { fprintf(stderr, "TfLiteInterpreterOptionsCreate failed\n"); result = 4; goto cleanup; }
  TfLiteInterpreterOptionsSetNumThreads(options, 1);
  interpreter = TfLiteInterpreterCreate(model, options);
  if (!interpreter) { fprintf(stderr, "TfLiteInterpreterCreate failed\n"); result = 5; goto cleanup; }
  if (TfLiteInterpreterAllocateTensors(interpreter) != kTfLiteOk) {
    fprintf(stderr, "AllocateTensors failed\n"); result = 6; goto cleanup;
  }
  if (TfLiteInterpreterGetInputTensorCount(interpreter) <= 0) {
    fprintf(stderr, "model has no input tensors\n"); result = 7; goto cleanup;
  }
  const TfLiteTensor *in = TfLiteInterpreterGetInputTensor(interpreter, 0);
  if (!in) { fprintf(stderr, "missing input tensor\n"); result = 7; goto cleanup; }
  const size_t input_bytes = TfLiteTensorByteSize(in);
  void *input_data = TfLiteTensorData(in);
  if (input_bytes == 0 || !input_data) {
    fprintf(stderr, "input tensor has no writable data\n"); result = 7; goto cleanup;
  }
  printf("input type=%d bytes=%zu dims=", TfLiteTensorType(in), input_bytes);
  for (int d = 0; d < TfLiteTensorNumDims(in); ++d) printf("%s%d", d ? "x" : "", TfLiteTensorDim(in, d));
  puts("");
  if (TfLiteTensorType(in) == kTfLiteFloat32) {
    if (input_bytes % sizeof(float) != 0) { fprintf(stderr, "input tensor byte size is not float-aligned\n"); result = 8; goto cleanup; }
    float *p = (float *)input_data;
    for (size_t i = 0; i < input_bytes / sizeof(float); ++i) p[i] = 0.0f;
  } else if (TfLiteTensorType(in) == kTfLiteUInt8) {
    const TfLiteQuantizationParams q = TfLiteTensorQuantizationParams(in);
    if (q.scale != 0.0f && (q.zero_point < 0 || q.zero_point > 255)) {
      fprintf(stderr, "UInt8 input tensor has invalid quantization zero_point: %d\n", q.zero_point);
      result = 12;
      goto cleanup;
    }
    const uint8_t fill = (q.scale != 0.0f) ? (uint8_t)q.zero_point : 0;
    uint8_t *p = (uint8_t *)input_data;
    for (size_t i = 0; i < input_bytes; ++i) p[i] = fill;
  } else if (TfLiteTensorType(in) == kTfLiteInt8) {
    int8_t *p = (int8_t *)input_data;
    for (size_t i = 0; i < input_bytes; ++i) p[i] = 0;
  } else if (TfLiteTensorType(in) == kTfLiteInt32) {
    if (input_bytes % sizeof(int32_t) != 0) { fprintf(stderr, "input tensor byte size is not int32-aligned\n"); result = 8; goto cleanup; }
    int32_t *p = (int32_t *)input_data;
    for (size_t i = 0; i < input_bytes / sizeof(int32_t); ++i) p[i] = 0;
  } else {
    fprintf(stderr, "unsupported deterministic input type %d\n", TfLiteTensorType(in)); result = 8; goto cleanup;
  }
  if (TfLiteInterpreterInvoke(interpreter) != kTfLiteOk) { fprintf(stderr, "Invoke failed\n"); result = 9; goto cleanup; }
  if (TfLiteInterpreterGetOutputTensorCount(interpreter) <= 0) {
    fprintf(stderr, "model has no output tensors\n"); result = 10; goto cleanup;
  }
  const TfLiteTensor *out = TfLiteInterpreterGetOutputTensor(interpreter, 0);
  if (!out) { fprintf(stderr, "missing output tensor\n"); result = 10; goto cleanup; }
  if (TfLiteTensorByteSize(out) == 0 || !TfLiteTensorData(out)) {
    fprintf(stderr, "output tensor has no readable data\n"); result = 10; goto cleanup;
  }
  printf("invoke=ok output type=%d bytes=%zu\n", TfLiteTensorType(out), TfLiteTensorByteSize(out));
  if (!print_scalar(out)) { result = 11; goto cleanup; }

cleanup:
  if (interpreter) TfLiteInterpreterDelete(interpreter);
  if (options) TfLiteInterpreterOptionsDelete(options);
  if (model) TfLiteModelDelete(model);
  return result;
}
