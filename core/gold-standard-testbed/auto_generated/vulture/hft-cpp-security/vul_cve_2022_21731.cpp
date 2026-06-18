// Vulnerable: VUL-CVE-2022-21731
// Minimum required number of dimensions.
  const int min_rank = concat_dim < 0 ? -concat_dim : concat_dim + 1;

  ShapeHandle output_before;
// --- concat_op_test.py ---
import numpy as np

from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
...
        gen_array_ops.concat_v2([t1, t2], 1).eval()

  def testConcatNegativeAxis(self):
    with test_util.use_gpu():
