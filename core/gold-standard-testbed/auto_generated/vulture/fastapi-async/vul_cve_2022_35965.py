# Vulnerable: VUL-CVE-2022-35965
out_type=dtype), array_ops.zeros([2, 0], dtype))

  def testInt64(self):
// --- searchsorted_op.cc ---
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_shape.h"
#include "tensorflow/core/lib/core/bits.h"
#include "tensorflow/core/platform/logging.h"
...
    const auto sorted_inputs = sorted_inputs_t.template flat<T>();
    const auto values = values_t.template flat<T>();
...
    const auto values = values_t.template flat<T>();
    OP_REQUIRES_OK(
        ctx, functor::LowerBoundFunctor<Device, T, OutType>::Compute(
