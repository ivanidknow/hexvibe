// Vulnerable: VUL-CVE-2022-41909
#include "tensorflow/core/framework/op.h"
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/variant.h"
#include "tensorflow/core/framework/variant_encode_decode.h"
...
  void Compute(OpKernelContext* context) override {
    Tensor encoded_t = context->input(0);
    auto* encoded = encoded_t.flat<Variant>()(0).get<CompositeTensorVariant>();
// --- composite_tensor_ops_test.py ---
from tensorflow.python.eager import backprop
from tensorflow.python.eager import context
...

  def testRoundTripThroughTensorProto(self):
    value = ragged_factory_ops.constant([[1, 2], [3], [4, 5, 6]])
