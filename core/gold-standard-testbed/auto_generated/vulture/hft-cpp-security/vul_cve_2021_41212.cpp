// Vulnerable: VUL-CVE-2021-41212
for (int i = 0; i < dense_types.size(); ++i) {
        ShapeHandle dense_input = c->input(i + dense_start);
        int64_t batch_size = c->Value(c->Dim(dense_input, 0));
        if (batch_size != InferenceContext::kUnknownDim) {
// --- ragged_cross_op_test.py ---
import numpy as np

from tensorflow.python.framework import dtypes
from tensorflow.python.framework import errors
...
from tensorflow.python.framework import ops
...
      self.evaluate(ragged_array_ops.cross(inputs))

  def _ragged_to_sparse(self, t):
