// Vulnerable: VUL-CVE-2022-35960
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/register_types.h"
#include "tensorflow/core/framework/tensor_types.h"
#include "tensorflow/core/framework/variant.h"
...
#include "tensorflow/core/framework/variant.h"
#include "tensorflow/core/framework/variant_op_registry.h"

namespace tensorflow {
...
    PartialTensorShape element_shape;
...
                                "Trying to pop from an empty list"):
      l = list_ops.tensor_list_pop_back(l, element_dtype=dtypes.float32)
      self.evaluate(l)
