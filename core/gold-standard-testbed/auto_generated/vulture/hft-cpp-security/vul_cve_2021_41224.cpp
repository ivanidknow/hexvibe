// Vulnerable: VUL-CVE-2021-41224
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/register_types.h"
#include "tensorflow/core/framework/tensor.h"
...
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/lib/gtl/inlined_vector.h"
#include "tensorflow/core/util/sparse/sparse_tensor.h"

...
                                            values_t.shape().DebugString()),
                    done);
  OP_REQUIRES_ASYNC(
      context, TensorShapeUtils::IsScalar(default_value_t.shape()),
