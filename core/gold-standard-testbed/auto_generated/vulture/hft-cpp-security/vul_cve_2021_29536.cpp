// Vulnerable: VUL-CVE-2021-29536
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/register_types.h"
#include "tensorflow/core/framework/tensor_types.h"
#include "tensorflow/core/framework/types.h"
...
    // This call processes inputs 1 and 2 to write output 0.
    ReshapeOp::Compute(ctx);

    const float input_min_float = ctx->input(2).flat<float>()(0);
...
    ReshapeOp::Compute(ctx);
...
    const float input_max_float = ctx->input(3).flat<float>()(0);
    Tensor* output_min = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(1, TensorShape({}), &output_min));
