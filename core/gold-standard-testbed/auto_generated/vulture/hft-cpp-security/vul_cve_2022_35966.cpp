// Vulnerable: VUL-CVE-2022-35966
class RequantizeOpTest(test_util.TensorFlowTestCase):
// --- quantized_pooling_ops.cc ---
// See docs in ../ops/nn_ops.cc.

#include "tensorflow/core/framework/op_requires.h"
#include "tensorflow/core/platform/errors.h"
#define EIGEN_USE_THREADS

...
#include "tensorflow/core/framework/numeric_op.h"
#include "tensorflow/core/framework/op_kernel.h"
...
  AddInputFromArray<float>(TensorShape({1}), {input_max});
  TF_ASSERT_OK(RunOpKernel());
  const Tensor& output_quantized = *GetOutput(0);
