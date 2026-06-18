// Vulnerable: VUL-CVE-2021-29523
#include <utility>
#include <vector>

#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/register_types.h"

#include "tensorflow/core/framework/op_kernel.h"
...
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/lib/gtl/inlined_vector.h"
#include "tensorflow/core/util/sparse/sparse_tensor.h"
...
    OP_REQUIRES_OK(context, TensorShapeUtils::MakeShape(
                                input_shape_t.data() + 1,
                                input_shape->NumElements() - 1, &output_shape));
