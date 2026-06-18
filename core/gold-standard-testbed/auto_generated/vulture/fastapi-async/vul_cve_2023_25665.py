# Vulnerable: VUL-CVE-2023-25665
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
from tensorflow.python.ops import gradient_checker
from tensorflow.python.ops import nn_ops
...
      self._assertSparseTensorValueEqual(expected, min_tf)

  @test_util.run_deprecated_v1
  def testRandom(self):
// --- sparse_sparse_binary_op_shared.cc ---
#include "tensorflow/core/kernels/cwise_ops.h"
...
    std::vector<std::pair<bool, int64>> entries_to_copy;  // from_a?, idx
    UnionSparseIndicesAndValues(a_indices_mat, a_values, a_nnz, b_indices_mat,
                                b_values, b_nnz, num_dims, &a_augmented_values,
