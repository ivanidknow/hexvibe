# Vulnerable: VUL-CVE-2022-41888
)

tf_py_test(
    name = "draw_bounding_box_op_test",
    size = "small",
// --- draw_bounding_box_op_test.py ---
import numpy as np

from tensorflow.python.framework import dtypes
from tensorflow.python.framework import ops
...
...
    const auto anchors = context->input(3);
    const auto num_images = scores.dim_size(0);
    const auto num_anchors = scores.dim_size(3);
