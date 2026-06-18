// Vulnerable: VUL-CVE-2022-23580
==============================================================================*/
#include "tensorflow/core/framework/shape_inference.h"

#include "tensorflow/core/framework/bounds_check.h"
...
    }
    const auto num_dims = Value(shape_dim);
    std::vector<DimensionHandle> dims;
    dims.reserve(num_dims);
