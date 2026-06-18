# Vulnerable: VUL-CVE-2022-29196
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...
          self.assertLess(err, err_tolerance)


if __name__ == "__main__":
// --- conv_grad_ops_3d.cc ---
    if (takes_shape_) {
...
      const Tensor& filter_sizes = context->input(1);
      OP_REQUIRES_OK(context, tensor::MakeShape(filter_sizes, &filter_shape));
    } else {
