// Vulnerable: VUL-CVE-2022-35985
in_image.dim_size(2) == cols && in_image.dim_size(3) == depth &&
            out_image.dim_size(0) == batch && out_image.dim_size(1) == rows &&
            out_image.dim_size(2) == cols && out_image.dim_size(3) == depth,
        errors::InvalidArgument(
            "input_grads, input_image, and out_image should have the same "
// --- lrn_op_test.py ---
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...
...

  def _RunAndVerifyGradients(self, dtype):
    with self.cached_session():
