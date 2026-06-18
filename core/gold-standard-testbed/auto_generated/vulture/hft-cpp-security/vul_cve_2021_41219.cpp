// Vulnerable: VUL-CVE-2021-41219
#include "tensorflow/core/lib/core/blocking_counter.h"
#include "tensorflow/core/lib/core/threadpool.h"
#include "tensorflow/core/platform/logging.h"
#include "tensorflow/core/platform/macros.h"
...
                    "Matrix size incompatible: a: ", a.shape().DebugString(),
                    ", b: ", b.shape().DebugString()));
    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, TensorShape({m, n}), &output));
...
    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, TensorShape({m, n}), &output));

    if (k == 0) {
