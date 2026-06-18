// Vulnerable: VUL-CVE-2021-37656
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"

namespace tensorflow {
...
        context, context->input_list("rt_nested_splits", &rt_nested_splits_in));
    const int rt_nested_splits_len = rt_nested_splits_in.size();
    DCHECK_GT(rt_nested_splits_len, 0);  // Enforced by REGISTER_OP.
    std::vector<ConstFlatSplits> rt_nested_splits;
    rt_nested_splits.reserve(rt_nested_splits_len);
...
...
        return InvalidArgument("First value of ragged splits must be 0.");
      }
      if (i > 0) {
