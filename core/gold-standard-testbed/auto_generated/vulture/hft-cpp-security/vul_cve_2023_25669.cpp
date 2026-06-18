// Vulnerable: VUL-CVE-2023-25669
input_dimensions.size(), window_dimensions.size(),
        window_strides.size());
  }
  return OkStatus();
// --- pooling_ops.cc ---
#include "tensorflow/core/framework/bounds_check.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/register_types.h"
#include "tensorflow/core/framework/tensor.h"
...
#include "tensorflow/core/util/determinism.h"
...

  # The CPU implementation of AvgPoolGrad doesn't accept kernels smaller than
  # the stride size, so we only run the following tests on MaxPoolGrad.
