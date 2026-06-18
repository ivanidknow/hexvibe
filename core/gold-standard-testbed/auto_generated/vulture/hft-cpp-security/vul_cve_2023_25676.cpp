// Vulnerable: VUL-CVE-2023-25676
#include <algorithm>
#include <ostream>

#include "tensorflow/core/framework/common_shape_fns.h"
...
          return errors::InvalidArgument(
              "All input shapes must be fully defined.");
        }
        DimensionHandle unused;
// --- array_ops_test.py ---
from tensorflow.python.framework import dtypes
...
    with self.assertRaisesRegex(errors.InvalidArgumentError,
                                r"0th dimension of value .* is less than"):
      f()
