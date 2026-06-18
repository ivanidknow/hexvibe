// Vulnerable: VUL-CVE-2020-26267
#include "tensorflow/core/kernels/data_format_ops.h"
#include "third_party/eigen3/unsupported/Eigen/CXX11/Tensor"
#include "tensorflow/core/framework/op_kernel.h"
...
#include "tensorflow/core/framework/register_types.h"
#include "tensorflow/core/framework/tensor.h"

namespace tensorflow {
...
typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;
...
...
      y_val = self.evaluate(y)
      self.assertAllEqual(y_val, [[7, 4], [4, 5], [5, 1], [9, 3]])
