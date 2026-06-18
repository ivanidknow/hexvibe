# Vulnerable: VUL-CVE-2021-37679
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import sparse_tensor
from tensorflow.python.framework import test_util
...
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
from tensorflow.python.ops import math_ops as mo
from tensorflow.python.ops import string_ops
...
    self.assertAllEqual(id_t2, [[0, 5], [0, 4]])

...
  for (int i = 0; i < ragged_components.size(); i++) {
    auto component_values_flat =
        ragged_components[i].values().flat_outer_dims<VALUE_TYPE, 2>();
