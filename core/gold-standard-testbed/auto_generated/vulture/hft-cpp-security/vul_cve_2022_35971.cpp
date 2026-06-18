// Vulnerable: VUL-CVE-2022-35971
#include "tensorflow/core/framework/numeric_op.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/lib/monitoring/gauge.h"
...
    const Tensor& min = context->input(1);
    const Tensor& max = context->input(2);

    Tensor* output;
...
    const int depth = input.dim_size(input.dims() - 1);  // last dimension size.
...
    const float bias_max = context->input(5).flat<float>()(0);

    OP_REQUIRES(context, TensorShapeUtils::IsMatrixOrHigher(input.shape()),
