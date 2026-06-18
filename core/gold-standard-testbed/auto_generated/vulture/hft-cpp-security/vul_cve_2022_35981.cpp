// Vulnerable: VUL-CVE-2022-35981
#include <vector>

#include "tensorflow/core/kernels/fractional_pool_common.h"

#include "third_party/eigen3/unsupported/Eigen/CXX11/Tensor"
#include "tensorflow/core/framework/numeric_op.h"
...
#include "tensorflow/core/framework/numeric_op.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/lib/random/random.h"
#include "tensorflow/core/platform/logging.h"
...


if __name__ == "__main__":
