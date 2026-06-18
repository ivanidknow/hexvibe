// Vulnerable: VUL-CVE-2022-35984
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"
#include "tensorflow/core/kernels/stateless_random_ops.h"
#include "tensorflow/core/lib/random/random_distributions.h"
...
                errors::InvalidArgument("Shape tensor must not be empty, got ",
                                        shape_tensor.DebugString()));
    int32_t num_batches = shape_tensor.flat<int32>()(0);

    int32_t samples_per_batch = 1;
    const int32_t num_dims = shape_tensor.dim_size(0);
...

  def testStatelessParameterizedTruncatedNormalHasGrads(self):
    mean = variables.Variable(0.01)
