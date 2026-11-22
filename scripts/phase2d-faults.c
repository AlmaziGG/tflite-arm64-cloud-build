/* Test-only caller-side injection. No changes to the TFLite DSO or measured harness. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tensorflow/lite/core/c/c_api_experimental.h"

static int fault(const char *name) {
    const char *value=getenv("P2D_TEST_FAULT");
    return value && !strcmp(value,name);
}
static TfLiteStatus invoke_test(TfLiteInterpreter *it) {
    if (fault("timeout")) sleep(10);
    if (fault("sigill")) raise(SIGILL);
    if (fault("crash")) raise(SIGABRT);
    if (fault("interrupt")) raise(SIGTERM);
    return fault("invoke") ? kTfLiteError : TfLiteInterpreterInvoke(it);
}
static void delete_test(TfLiteInterpreter *it) {
    TfLiteInterpreterDelete(it);
    if (fault("teardown")) raise(SIGABRT);
}
#define TfLiteInterpreterAllocateTensors(it) (fault("allocate")?kTfLiteError:TfLiteInterpreterAllocateTensors(it))
#define TfLiteTensorType(t) (fault("type")?kTfLiteFloat32:TfLiteTensorType(t))
#define TfLiteTensorDim(t,i) (fault("shape")?0:TfLiteTensorDim(t,i))
#define TfLiteInterpreterGetOutputTensor(it,i) (fault("output")?NULL:TfLiteInterpreterGetOutputTensor(it,i))
#define TfLiteInterpreterResetVariableTensors(it) (fault("reset")?kTfLiteError:TfLiteInterpreterResetVariableTensors(it))
#define TfLiteInterpreterInvoke invoke_test
#define TfLiteInterpreterDelete delete_test
#include "phase2d-probe.c"
