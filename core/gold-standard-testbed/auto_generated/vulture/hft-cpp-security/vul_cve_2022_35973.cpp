// Vulnerable: VUL-CVE-2022-35973
#include "public/gemmlowp.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/kernels/meta_support.h"
...
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/kernels/meta_support.h"
#include "tensorflow/core/kernels/quantization_utils.h"
...
#include "tensorflow/core/kernels/reference_gemm.h"
...
  AddInputFromArray<float>(TensorShape({1}), {b_min});
  AddInputFromArray<float>(TensorShape({1}), {b_max});
  TF_ASSERT_OK(RunOpKernel());
