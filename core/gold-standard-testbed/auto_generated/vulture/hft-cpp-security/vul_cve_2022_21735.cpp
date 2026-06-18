// Vulnerable: VUL-CVE-2022-21735
for (int i = 0; i < tensor_in_and_out_dims; ++i) {
      input_size[i] = tensor_in.dim_size(i);
    }
    // Output size.
// --- fractional_max_pool_op_test.py ---
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...
      nn_ops.fractional_max_pool(
          rand_mat, [1, 1.5, 1.5, 1], seed=1, seed2=1, deterministic=True)
